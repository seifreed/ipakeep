/*
MIT License

Copyright (c) 2021 Majd Alfhaily

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
*/

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

@interface IPAKeepCKSigningSession : NSObject
- (instancetype)initWithStoreClient:(id)storeClient;
- (void)openSessionWithCompletionHandler:(void (^)(void))completionHandler;
- (NSData *)signData:(NSData *)data error:(NSError **)error;
- (void)closeSession;
- (BOOL)isSessionOpen;
@end

static void *commerceKitHandle;
static void *appleMediaServicesHandle;
static char frameworkError[512];

static void loadFrameworks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        commerceKitHandle = dlopen(
            "/System/Library/PrivateFrameworks/CommerceKit.framework/CommerceKit",
            RTLD_LAZY | RTLD_LOCAL
        );
        appleMediaServicesHandle = dlopen(
            "/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices",
            RTLD_LAZY | RTLD_LOCAL
        );
        if (commerceKitHandle == NULL || appleMediaServicesHandle == NULL) {
            const char *message = dlerror();
            snprintf(frameworkError, sizeof(frameworkError), "%s",
                     message != NULL ? message : "could not load Apple Store frameworks");
        }
    });
}

static void setError(char **destination, const char *message) {
    if (destination != NULL) {
        *destination = strdup(message != NULL ? message : "unknown Apple Store error");
    }
}

static void setNSError(char **destination, NSError *error, const char *fallback) {
    setError(destination, error.localizedDescription.UTF8String ?: fallback);
}

static int storeSignature(const unsigned char *input, size_t inputLength,
                          unsigned char **output, size_t *outputLength,
                          char **errorMessage) {
    Class sessionClass = NSClassFromString(@"CKSigningSession");
    if (sessionClass == Nil) {
        setError(errorMessage, "CKSigningSession is unavailable in CommerceKit");
        return 1;
    }

    IPAKeepCKSigningSession *session = [(id)[sessionClass alloc] initWithStoreClient:nil];
    if (session == nil) {
        setError(errorMessage, "CommerceKit could not create a signing session");
        return 2;
    }

    dispatch_semaphore_t opened = dispatch_semaphore_create(0);
    @try {
        [session openSessionWithCompletionHandler:^{ dispatch_semaphore_signal(opened); }];
    } @catch (NSException *exception) {
        [session closeSession];
        setError(errorMessage, exception.reason.UTF8String ?: "Apple SAP session could not open");
        return 2;
    }
    if (dispatch_semaphore_wait(opened, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)) != 0) {
        [session closeSession];
        setError(errorMessage, "timed out opening the Apple SAP signing session");
        return 2;
    }
    if ([session respondsToSelector:@selector(isSessionOpen)] && ![session isSessionOpen]) {
        [session closeSession];
        setError(errorMessage, "Apple SAP signing session did not open");
        return 2;
    }

    NSData *data = [NSData dataWithBytes:input length:inputLength];
    NSError *signingError = nil;
    NSData *signature = nil;
    @try {
        signature = [session signData:data error:&signingError];
        [session closeSession];
    } @catch (NSException *exception) {
        [session closeSession];
        setError(errorMessage, exception.reason.UTF8String ?: "Apple SAP signing failed");
        return 2;
    }
    if (signature == nil || signature.length == 0) {
        setNSError(errorMessage, signingError, "CommerceKit returned no SAP signature");
        return 2;
    }

    unsigned char *copy = malloc(signature.length);
    if (copy == NULL) {
        setError(errorMessage, "could not allocate SAP signature output");
        return 2;
    }
    [signature getBytes:copy length:signature.length];
    *output = copy;
    *outputLength = signature.length;
    return 0;
}

static int storeAMDHeaders(const char *endpoint, char **amd, char **amdMachine,
                           char **errorMessage) {
    Class anisetteClass = NSClassFromString(@"AMSAnisette");
    SEL selector = sel_registerName("_headersForRequest:account:type:");
    if (anisetteClass == Nil || !class_respondsToSelector(object_getClass(anisetteClass), selector)) {
        setError(errorMessage, "AMSAnisette Store device proof is unavailable");
        return 1;
    }

    NSString *urlText = [NSString stringWithUTF8String:endpoint];
    NSURL *url = [NSURL URLWithString:urlText];
    if (url == nil || ![url.scheme isEqualToString:@"https"] ||
        ![url.host isEqualToString:@"auth.itunes.apple.com"]) {
        setError(errorMessage, "invalid native App Store authentication URL");
        return 2;
    }

    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    typedef id (*HeadersForRequest)(id, SEL, id, id, NSInteger);
    NSDictionary *values = nil;
    @try {
        values = ((HeadersForRequest)objc_msgSend)(anisetteClass, selector, request, nil, 2);
    } @catch (NSException *exception) {
        setError(errorMessage, exception.reason.UTF8String ?: "AMSAnisette failed to provide Store proof");
        return 2;
    }
    if (![values isKindOfClass:NSDictionary.class]) {
        setError(errorMessage, "macOS returned no Store device proof");
        return 1;
    }

    NSString *amdValue = values[@"X-Apple-AMD"];
    NSString *machineValue = values[@"X-Apple-AMD-M"];
    if (![amdValue isKindOfClass:NSString.class] ||
        ![machineValue isKindOfClass:NSString.class] ||
        amdValue.length == 0 || machineValue.length == 0 ||
        amdValue.length > 8192 || machineValue.length > 8192 ||
        [amdValue rangeOfCharacterFromSet:NSCharacterSet.newlineCharacterSet].location != NSNotFound ||
        [machineValue rangeOfCharacterFromSet:NSCharacterSet.newlineCharacterSet].location != NSNotFound) {
        setError(errorMessage, "macOS returned an incomplete Store device proof");
        return 1;
    }

    *amd = strdup(amdValue.UTF8String);
    *amdMachine = strdup(machineValue.UTF8String);
    if (*amd == NULL || *amdMachine == NULL) {
        free(*amd);
        free(*amdMachine);
        *amd = NULL;
        *amdMachine = NULL;
        setError(errorMessage, "could not allocate Store device proof output");
        return 2;
    }
    return 0;
}

int ipakeep_native_auth_headers(const char *endpoint,
                                const unsigned char *body, size_t bodyLength,
                                unsigned char **signature, size_t *signatureLength,
                                char **amd, char **amdMachine, char **errorMessage) {
    if (signature == NULL || signatureLength == NULL || amd == NULL || amdMachine == NULL) {
        setError(errorMessage, "invalid native authentication output parameters");
        return 2;
    }
    *signature = NULL;
    *signatureLength = 0;
    *amd = NULL;
    *amdMachine = NULL;
    if (errorMessage != NULL) *errorMessage = NULL;

    @autoreleasepool {
        loadFrameworks();
        if (commerceKitHandle == NULL || appleMediaServicesHandle == NULL) {
            setError(errorMessage, frameworkError);
            return 1;
        }

        int status = storeSignature(body, bodyLength, signature, signatureLength, errorMessage);
        if (status != 0) return status;
        status = storeAMDHeaders(endpoint, amd, amdMachine, errorMessage);
        if (status != 0) {
            free(*signature);
            *signature = NULL;
            *signatureLength = 0;
        }
        return status;
    }
}
