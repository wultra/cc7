/*
 * Copyright 2025 Wultra s.r.o.
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
#include <cc7tests/CC7Tests.h>
#include <cc7/objc/ObjcJson.h>

using namespace cc7;

@interface CC7ObjcTests : XCTestCase
@end

@implementation CC7ObjcTests
 
- (void)testObjcToJsonConversionAndViceVersa
{
    NSDictionary * dict = @{
        @"string": @"hello world",
        @"int": @32,
        @"double": @3.14,
        @"boolYes": @YES,
        @"boolNo": @NO,
        @"object": @{
            @"key1": @"value1",
            @"key2": @"value2"
        },
        @"null": [NSNull null],
        @"array": @[
            @YES,
            @"Hello",
            @3.14
        ]
    };
    
    auto json = objc::JsonValueFromObjC(dict);
    
    XCTAssertTrue(json::JsonValue("hello world") == json["string"]);
    XCTAssertTrue(json::JsonValue::integer(32) == json["int"]);
    XCTAssertTrue(json::JsonValue::number(3.14) == json["double"]);
    XCTAssertTrue(json::JsonValue::yes() == json["boolYes"]);
    XCTAssertTrue(json::JsonValue::no() == json["boolNo"]);
    XCTAssertTrue(json::JsonValue::null() == json["null"]);
    
    XCTAssertTrue(json::JsonValue::yes() == json["array"][0]);
    XCTAssertTrue(json::JsonValue("Hello") == json["array"][1]);
    XCTAssertTrue(json::JsonValue::number(3.14) == json["array"][2]);
    
    XCTAssertTrue("value1" == json.stringAtPath("object.key1"));
    XCTAssertTrue("value2" == json.stringAtPath("object.key2"));

    NSDictionary * repr = objc::JsonValueToObjC(json);
    XCTAssertEqualObjects(@"hello world", repr[@"string"]);
    XCTAssertEqualObjects(@32, repr[@"int"]);
    XCTAssertEqualObjects(@3.14, repr[@"double"]);
    XCTAssertEqualObjects(@YES, repr[@"boolYes"]);
    XCTAssertEqualObjects(@NO, repr[@"boolNo"]);
    XCTAssertEqualObjects(@"value1", ((NSDictionary*)repr[@"object"])[@"key1"]);
    XCTAssertEqualObjects(@"value2", ((NSDictionary*)repr[@"object"])[@"key2"]);
    XCTAssertEqualObjects([NSNull null], repr[@"null"]);
    XCTAssertEqualObjects(@YES, ((NSArray*)repr[@"array"])[0]);
    XCTAssertEqualObjects(@"Hello", ((NSArray*)repr[@"array"])[1]);
    XCTAssertEqualObjects(@3.14, ((NSArray*)repr[@"array"])[2]);
}


@end
