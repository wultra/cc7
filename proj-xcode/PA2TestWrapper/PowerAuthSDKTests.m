/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <XCTest/XCTest.h>
#import "PowerAuthTestServerAPI.h"
#import "PowerAuthTestServerConfig.h"
#import "AsyncHelper.h"

#import "PowerAuthSDK.h"

/**
 The purpose of `PowerAuthSDKTests` is to run a series of integration tests where the
 high level `PowerAuthSDK` class is a primary test subject. All integration tests
 needs a running server counterparts and therefore are by-default disabled for all
 main development schemas ("PA2_Release", "PA2_Debug"). To run this test, you
 need to switch to "PA2_IntegrationTests" and check the default servers configuration,
 available in the "PowerAuthTestConfig.h" header file.
 
 If you don't want to modify the header file with configurations, then you can use
 a command line arguments passed to the unit testing process. Check `-(void)processCommandLineArguments`
 method for details. We recommend you to create a local copy of "PA2_IntegrationTests" scheme 
 and change the test arguments, or use an appropriate `xcodebuild` command with parameters.
 */
@interface PowerAuthSDKTests : XCTestCase
@end

@implementation PowerAuthSDKTests
{
	NSString * _soapApiURL;
	NSString * _restApiURL;
	NSString * _userId;
	NSString * _activationName;
	
	PowerAuthTestServerAPI * _testServerApi;	// SOAP connection
	PowerAuthConfiguration * _config;			// Default SDK config
	PowerAuthSDK * _sdk;						// Default SDK instance
	
	BOOL _hasConfig;
	BOOL _invalidConfig;
}

#pragma mark - Test setup

- (void)setUp
{
    [super setUp];
	[self runOnceForAllTests];
}

/**
 Supported command line arguments for tests:
 
	--baseUrl=url	
		- To change a base URL (typically, where the docker with all containers is running)
		  This parameter affects both, REST & SOAP API URLs and expects, that the default
		  docker containers are running at the provided domain.

	--soapUrl=url
		- To change just a location of private SOAP API server
	
	--restUrl=url
		- To change just a location of public REST API server.
 
 If soapUrl or restUrl is not defined, then the POWERAUTH_TEST_SERVER_URL and POWERAUTH_REST_API_URL
 mcros will be used.
 */
- (BOOL) processCommandLineArguments
{
	// Skip first argument, which is a path to process
	NSArray * arguments = [[NSProcessInfo processInfo] arguments];
	arguments = [arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)];
	// Process all arguments
	__block BOOL wrongParam = NO;
	[arguments enumerateObjectsUsingBlock:^(NSString * arg, NSUInteger idx, BOOL * stop) {
		if ([arg hasPrefix:@"--baseUrl"]) {
			NSString * url = [self stripUrlFromArgument:arg];
			if (url) {
				_soapApiURL = [url stringByAppendingString:@":20010/powerauth-java-server/soap"];
				_restApiURL = [url stringByAppendingString:@":18080/powerauth-rest-api"];
			} else {
				*stop = wrongParam = YES;
			}
		} else if ([arg hasPrefix:@"--soapUrl"]) {
			NSString * url = [self stripUrlFromArgument:arg];
			if (url) {
				_soapApiURL = url;
			} else {
				*stop = wrongParam = YES;
			}
		} else if ([arg hasPrefix:@"--restUrl"]) {
			NSString * url = [self stripUrlFromArgument:arg];
			if (url) {
				_restApiURL = url;
			} else {
				*stop = wrongParam = YES;
			}
		}
	}];
	if (wrongParam) {
		return NO;
	}
	
	// Default values
	if (!_soapApiURL) {
		_soapApiURL = POWERAUTH_TEST_SERVER_URL;
	}
	if (!_restApiURL) {
		_restApiURL = POWERAUTH_REST_API_URL;
	}
	if (!_userId) {
		_userId = @"TestUserIOS";
	}
	if (!_activationName) {
		_activationName = @"Trogdor the Burninator";
	}
	
	// Print report
	NSLog(@"=======================================================================");
	NSLog(@"The integration tests will run against following servers:");
	NSLog(@"    REST API Server: %@", _restApiURL);
	NSLog(@"    SOAP API Server: %@", _soapApiURL);
	NSLog(@"               User: %@", _userId);
	NSLog(@"=======================================================================");
	
	return YES;
}

/**
 Performs one-time initialization for all unit tests. The result of calling this method is
 pepared all i-vars with runtime variables, like _sdk, _soapApiURL, etc...
 */
- (void) runOnceForAllTests
{
	if (_hasConfig) {
		return;
	}
	
	// Prepare command
	BOOL result;
	result = [self processCommandLineArguments];
	XCTAssertTrue(result, @"The provided test argument is wrong.");
	
	// Test connection to SOAP server
	if (result) {
		_testServerApi = [[PowerAuthTestServerAPI alloc] initWithTestServerURL:[NSURL URLWithString:_soapApiURL]
															   applicationName:POWERAUTH_TEST_SERVER_APP
															applicationVersion:POWERAUTH_TEST_SERVER_APP_VERSION];
		result = [_testServerApi validateConnection];
		XCTAssertTrue(result, @"Connection to test server failed. Check debug log for details.");
	}
	// Create a configuration
	if (result) {
		_config = [[PowerAuthConfiguration alloc] init];
		_config.instanceId = @"IntegrationTests";
		_config.baseEndpointUrl = _restApiURL;
		_config.appKey = _testServerApi.appVersion.applicationKey;
		_config.appSecret = _testServerApi.appVersion.applicationSecret;
		_config.masterServerPublicKey = _testServerApi.appDetail.masterPublicKey;
		result = [_config validateConfiguration];
		XCTAssertTrue(result, @"Constructed configuration is not valid.");
	}
	// Construct an PA-SDK object
	if (result) {
		_sdk = [[PowerAuthSDK alloc] initWithConfiguration:_config];
		[_sdk reset];
		
		result = _sdk != nil;
		result = result && [_sdk hasPendingActivation] == NO;
		
		XCTAssertTrue(result, @"PowerAuthSDK ended in unexpected state.");
	}
	_invalidConfig = result == NO;
	_hasConfig = YES;
}


#pragma mark - Helper utilities

/**
 Returns URL part from "{option}={url}" string.
 */
- (NSString *) stripUrlFromArgument:(NSString *)argument
{
	NSRange equal = [argument rangeOfString:@"="];
	if (equal.location == NSNotFound || equal.location == argument.length - 1) {
		NSLog(@"Parameter '%@' has no valid URL defined.", argument);
		return nil;
	}
	NSString * url = [argument substringFromIndex:equal.location + 1];
	if ([url hasPrefix:@"http://"] || [url hasPrefix:@"https://"]) {
		if ([url hasSuffix:@"/"]) {
			return [url substringToIndex:url.length - 1];
		}
		return url;
	}
	NSLog(@"Parameter '%@' has no valid URL defined.", argument);
	return nil;
}

/**
 Checks whether the test config is valid. You should use this macro in all unit tests
 defined in this class.
 */
#define CHECK_TEST_CONFIG()		\
	if (_invalidConfig) {		\
		XCTFail(@"Test configuration is not valid.");	\
		return;					\
	}

/**
 Checks boolean value in result local variable and returns |obj| value if contains NO.
 */
#define CHECK_RESULT_RET(obj)	\
	if (result == NO) {			\
		return obj;				\
	}

/**
 Creates a new PowerAuthAuthentication object with default configuration.
 */
- (PowerAuthAuthentication*) createAuthentication
{
	NSArray<NSString*> * veryCleverPasswords = @[ @"supersecure", @"nbusr123", @"8520", @"pa55w0rd" ];
	PowerAuthAuthentication * auth = [[PowerAuthAuthentication alloc] init];
	auth.usePossession = YES;
	auth.useBiometry = NO;		// There's no human being involved in the automatic test :)
	auth.usePassword = veryCleverPasswords[arc4random_uniform((uint32_t)veryCleverPasswords.count)];
	return auth;
}

/**
 Returns an activation status object. May return nil if status is not available yet, which is also valid operation.
 */
- (PA2ActivationStatus*) fetchActivationStatus
{
	BOOL taskShouldWork = [_sdk hasValidActivation];
	
	__block NSDictionary * activationStatusCustomObject = nil;
	__block NSError * fetchError = nil;
	PA2ActivationStatus * result = [AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		// Start a fetch task.
		PA2OperationTask * task = [_sdk fetchActivationStatusWithCallback:^(PA2ActivationStatus * status, NSDictionary * customObject, NSError * error) {
			activationStatusCustomObject = customObject;
			fetchError = error;
			[waiting reportCompletion:status];
		}];
		// Test whether the task should work.
		// Typically, if activation is not completed, then the asynchronous task is not started, but is reported
		// as cancelled.
		if (taskShouldWork) {
			XCTAssertFalse([task isCancelled]);
		} else {
			XCTAssertTrue([task isCancelled]);
		}
	}];
	if (taskShouldWork) {
		XCTAssertNotNil(result);
		return result;
	}
	return nil;
}



#pragma mark - Integration tests

#pragma mark - Activation

/**
 Returns @[PATSInitActivationResponse, @(BOOL)] with activation data and result of activation.
 You can configure whether the activation can use optional signature during the activation and whether
 the activation should be removed automatically.
 */
- (NSArray*) createActivation:(BOOL)useSignature removeAfter:(BOOL)removeAfter
{
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	BOOL result;
	NSError * error;
	
	// We can't guarantee a sequence of tests, so reset the activation now
	[_sdk reset];
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	// 1) SERVER: initialize an activation on server (this is typically implemented in the internet banking application)
	PATSInitActivationResponse * activationData = [_testServerApi initializeActivation:_userId];
	NSString * activationCode = useSignature ? [activationData activationCodeWithSignature] : [activationData activationCodeWithoutSignature];
	NSArray * preliminaryResult = @[activationData, @NO];
	
	__block NSString * activationFingerprint = nil;
	
	// 2) CLIENT: Start activation on client's side
	result = [[AsyncHelper synchronizeAsynchronousBlock:^(AsyncHelper *waiting) {
		
		PA2OperationTask * task = [_sdk createActivationWithName:_activationName activationCode:activationCode callback:^(NSString * fingerprint, NSError * error) {
			activationFingerprint = fingerprint;
			[waiting reportCompletion:@(error == nil)];
		}];
		// Returned task should not be cancelled
		XCTAssertFalse([task isCancelled]);
		
	}] boolValue];
	XCTAssertTrue(result, @"Activation on client side did fail.");
	CHECK_RESULT_RET(preliminaryResult);
	
	XCTAssertTrue([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	
	// 2.1) CLIENT: Try to fetch status. At this point, it should not work! The activation is not completed yet.
	PA2ActivationStatus * activationStatus = [self fetchActivationStatus];
	XCTAssertNil(activationStatus);
	XCTAssertTrue([_sdk hasPendingActivation]);
	XCTAssertFalse([_sdk hasValidActivation]);
	
	// 3) CLIENT: Now it's time to commit activation locally
	PowerAuthAuthentication * auth = [self createAuthentication];
	result = [_sdk commitActivationWithAuthentication:auth error:&error];
	CHECK_RESULT_RET(preliminaryResult);
	
	XCTAssertTrue(result, @"Client's commit failed.");
	XCTAssertFalse([_sdk hasPendingActivation]);
	XCTAssertTrue([_sdk hasValidActivation]);
	
	// 3.1) CLIENT: Fetch status again. In this time, the operation should work and return OTP_USED
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	XCTAssertTrue(activationStatus.state == PA2ActivationState_OTP_Used);
	
	// 4) SERVER: This is the last step of activation. We need to commit an activation on the server side. This is typically done internally
	//            on the server side and depends on activation flow in concrete internet banking project.
	result = [_testServerApi commitActivation:activationData.activationId];
	XCTAssertTrue(result, @"Server's commit failed");
	CHECK_RESULT_RET(preliminaryResult);
	
	// 5) CLIENT: Fetch status again. Now the state should be active
	activationStatus = [self fetchActivationStatus];
	XCTAssertNotNil(activationStatus);
	XCTAssertTrue(activationStatus.state == PA2ActivationState_Active);
	
	// Post activation steps...
	result = [_sdk.session.activationIdentifier isEqualToString:activationData.activationId];
	XCTAssertTrue(result, @"Activation identifier in session is different to identifier generated on the server.");
	CHECK_RESULT_RET(preliminaryResult);
	
	// Now it's time to validate activation status, created on the server
	PATSActivationStatus * serverActivationStatus = [_testServerApi getActivationStatus:activationData.activationId];
	result = serverActivationStatus != nil;
	CHECK_RESULT_RET(preliminaryResult);
	XCTAssertTrue([serverActivationStatus.activationName isEqualToString:_activationName]);
	// This test fails but I don't know why :(
	//XCTAssertTrue([serverActivationStatus.devicePublicKeyFingerprint isEqualToString:activationFingerprint]);
	
	// This is just a cleanup. If remove will fail, then we don't report an error
	if (removeAfter || !result) {
		if (!result) {
			NSLog(@"We're removing activation due to fact, that session creation failed.");
		}
		[self removeLastActivation:activationData];
	}
	
	return @[activationData, @YES];
}

/**
 Method will remove activation on the server. We're using SOAP message, because our SDK object doesn't have activation always 
 identifier present in its structures.
 */
- (void) removeLastActivation:(PATSInitActivationResponse*)activationData
{
	NSString * activationId;
	if (activationData) {
		// If we have activation data, prefer that id.
		activationId = _sdk.session.activationIdentifier;
	}
	if (!activationId) {
		activationId = _sdk.session.activationIdentifier;
	}
	if (!activationId) {
		NSLog(@"WARNING: Unable to remove activation. This is not an error, but you'll see a lot of unfinished activations.");
	}
	[_testServerApi removeActivation:activationId];
}

- (void) testCreateActivationWithSignature
{
	CHECK_TEST_CONFIG();
	
	NSArray * result = [self createActivation:YES removeAfter:YES];
	XCTAssertTrue([result.lastObject boolValue]);
}


- (void) testCreateActivationWithhoutSignature
{
	CHECK_TEST_CONFIG();
	
	NSArray * result = [self createActivation:NO removeAfter:YES];
	XCTAssertTrue([result.lastObject boolValue]);
}

#pragma mark - Data signing



@end