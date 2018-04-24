



#import "HighQEncryptor.h"
#import "NSData+Base64.h"
#import <CommonCrypto/CommonCryptor.h>
@implementation HighQEncryptor

#pragma mark -
#pragma mark Initialization and deallcation


#pragma mark -
#pragma mark Praivate


#pragma mark -
#pragma mark API

+ (NSData*)encryptData:(NSData*)data key:(NSData*)key iv:(NSData*)iv;
{
    NSData* result = nil;
    
    // setup key
    unsigned char cKey[FBENCRYPT_KEY_SIZE];
	bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:FBENCRYPT_KEY_SIZE];
	
    // setup iv
    char cIv[FBENCRYPT_BLOCK_SIZE];
    bzero(cIv, FBENCRYPT_BLOCK_SIZE);
    if (iv) {
        [iv getBytes:cIv length:FBENCRYPT_BLOCK_SIZE];
    }
    
    // setup output buffer
	size_t bufferSize = [data length] + FBENCRYPT_BLOCK_SIZE;

	void *buffer = malloc(bufferSize);
    
    // do encrypt
	size_t encryptedSize = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          FBENCRYPT_ALGORITHM,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          cKey,
                                          FBENCRYPT_KEY_SIZE,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
										  &encryptedSize);
	if (cryptStatus == kCCSuccess) {
		result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
	} else {
        free(buffer);
        NSLog(@"[ERROR] failed to encrypt|CCCryptoStatus: %d", cryptStatus);
    }
	
	return result;
}

+ (NSData*)decryptData:(NSData*)data key:(NSData*)key iv:(NSData*)iv;
{
    NSData* result = nil;
    
    // setup key
    unsigned char cKey[FBENCRYPT_KEY_SIZE];
	bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:FBENCRYPT_KEY_SIZE];
    
    // setup iv
    char cIv[FBENCRYPT_BLOCK_SIZE];
    bzero(cIv, FBENCRYPT_BLOCK_SIZE);
    if (iv) {
        [iv getBytes:cIv length:FBENCRYPT_BLOCK_SIZE];
    }
    
    // setup output buffer
	size_t bufferSize = [data length] + FBENCRYPT_BLOCK_SIZE;
	void *buffer = malloc(bufferSize);
	
    // do decrypt
	size_t decryptedSize = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          FBENCRYPT_ALGORITHM,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
										  cKey,
                                          FBENCRYPT_KEY_SIZE,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
	
	if (cryptStatus == kCCSuccess) {
		result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
	} else {
        free(buffer);
        NSLog(@"[ERROR] failed to decrypt| CCCryptoStatus: %d", cryptStatus);
    }
    
	return result;
}


+ (NSString*)encryptBase64String:(NSString*)string
{
    NSString *keyString = @"DH28aHprpIxJFaOz962UO4BPqA7N1je5";
    NSData* data = [self encryptData:[string dataUsingEncoding:NSUTF8StringEncoding]
                                 key:[NSData dataFromBase64String:keyString]
                                  iv:nil];
    return [data base64EncodedStringWithSeparateLines:YES];
}

+ (NSString*)decryptBase64String:(NSString*)encryptedBase64String
{
    NSString *keyString = @"DH28aHprpIxJFaOz962UO4BPqA7N1je5";
    NSData* encryptedData = [NSData dataFromBase64String:encryptedBase64String];
    NSData* data = [self decryptData:encryptedData
                                 key:[NSData dataFromBase64String:keyString]
                                  iv:nil];
    if (data) {
        return [[NSString alloc] initWithData:data
                                      encoding:NSUTF8StringEncoding];
    } else {
        return nil;
    }
}


#define FBENCRYPT_IV_HEX_LEGNTH (FBENCRYPT_BLOCK_SIZE*2)

+ (NSData*)generateIv
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        srand(time(NULL));
    });
    
    char cIv[FBENCRYPT_BLOCK_SIZE];
    for (int i=0; i < FBENCRYPT_BLOCK_SIZE; i++) {
        cIv[i] = rand() % 256;
    }
    return [NSData dataWithBytes:cIv length:FBENCRYPT_BLOCK_SIZE];
}


+ (NSString*)hexStringForData:(NSData*)data
{
    if (data == nil) {
        return nil;
    }
    
    NSMutableString* hexString = [NSMutableString string];
    
    const unsigned char *p = [data bytes];
    
    for (int i=0; i < [data length]; i++) {
        [hexString appendFormat:@"%02x", *p++];
    }
    return hexString;
}

+ (NSData*)dataForHexString:(NSString*)hexString
{
    if (hexString == nil) {
        return nil;
    }
    
    const char* ch = [[hexString lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* data = [NSMutableData data];
    while (*ch) {
        char byte = 0;
        if ('0' <= *ch && *ch <= '9') {
            byte = *ch - '0';
        } else if ('a' <= *ch && *ch <= 'f') {
            byte = *ch - 'a' + 10;
        }
        ch++;
        byte = byte << 4;
        if (*ch) {
            if ('0' <= *ch && *ch <= '9') {
                byte += *ch - '0';
            } else if ('a' <= *ch && *ch <= 'f') {
                byte += *ch - 'a' + 10;
            }
            ch++;
        }
        [data appendBytes:&byte length:1];
    }
    return data;
}

#pragma mark -
#pragma mark Encrypt and Decrypt Method

+(NSString*)doCipher:(NSString*)message key:(NSString*)key operation:(CCOperation)encryptOrDecrypt {
    const void *messageData;
    size_t messageBufferSize;
    
    if (encryptOrDecrypt == kCCDecrypt){
        NSData *messageEncryptData= [NSData dataFromBase64String:message];
        messageBufferSize= [messageEncryptData length];
        messageData= [messageEncryptData bytes];
    }
    else{
        messageBufferSize= message.length;
        messageData = [[[message dataUsingEncoding: NSUTF8StringEncoding]mutableCopy] bytes];
    }
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (messageBufferSize + FBENCRYPT_BLOCK_SIZE) & ~(FBENCRYPT_BLOCK_SIZE - 1);
    
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
//    uint8_t iv[kCCBlockSize3DES];
    uint8_t iv[FBENCRYPT_BLOCK_SIZE];

    memset((void *) iv, 0x0, (size_t) sizeof(iv));
    
    //    NSMutableData *keyData = [[key dataUsingEncoding:NSUTF8StringEncoding]mutableCopy];
    //    NSData *keyEncodedMD5 = [NSData MD5Digest:keyData];
    
    NSData *keyEncodedMD5 = [NSData dataFromBase64String:key];
    
    NSMutableData *keyDataAux = [NSMutableData dataWithData:keyEncodedMD5];
    NSRange rangeToModify = NSMakeRange([keyEncodedMD5 length], FBENCRYPT_KEY_SIZE - [keyEncodedMD5 length]);
    [keyDataAux setLength: FBENCRYPT_KEY_SIZE];
    [keyDataAux replaceBytesInRange:rangeToModify withBytes:[keyEncodedMD5 bytes]];
    
    ccStatus = CCCrypt(encryptOrDecrypt, // CCoperation op
                       FBENCRYPT_ALGORITHM, // CCAlgorithm alg
                       kCCOptionPKCS7Padding, // CCOptions
                       [keyDataAux bytes], // const void *key
                       FBENCRYPT_KEY_SIZE, // 3DES key size length 24 bytes
                       nil,  //const void *iv,
                       messageData, // const void *dataIn
                       messageBufferSize, // size_t dataInLength
                       (void *)bufferPtr, // void *dataOut
                       bufferPtrSize, // size_t dataOutAvailable
                       &movedBytes); // size_t *dataOutMoved
    
    if (ccStatus == kCCParamError) return @"PARAM ERROR";
    else if (ccStatus == kCCBufferTooSmall) return @"BUFFER TOO SMALL";
    else if (ccStatus == kCCMemoryFailure) return @"MEMORY FAILURE";
    else if (ccStatus == kCCAlignmentError) return @"ALIGNMENT";
    else if (ccStatus == kCCDecodeError) return @"DECODE ERROR";
    else if (ccStatus == kCCUnimplemented) return @"UNIMPLEMENTED";
    
    NSString *result;
    if (encryptOrDecrypt == kCCDecrypt){
        result = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes] encoding:NSUTF8StringEncoding] ;
    }
    else{
        NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
        result= [myData base64EncodedString];
    }
    return result;
}


+(NSData *)base64DataFromString: (NSString *)string {
    unsigned long ixtext, lentext;
    unsigned char ch, input[4], output[3];
    short i, ixinput;
    Boolean flignore, flendtext = false;
    const char *temporary;
    NSMutableData *result;
    
    if (!string) {
        return [NSData data];
    }
    
    ixtext = 0;
    
    temporary = [string UTF8String];
    
    lentext = [string length];
    
    result = [NSMutableData dataWithCapacity: lentext];
    
    ixinput = 0;
    
    while (true) {
        if (ixtext >= lentext) {
            break;
        }
        
        ch = temporary[ixtext++];
        
        flignore = false;
        
        if ((ch >= 'A') && (ch <= 'Z')) {
            ch = ch - 'A';
        } else if ((ch >= 'a') && (ch <= 'z')) {
            ch = ch - 'a' + 26;
        } else if ((ch >= '0') && (ch <= '9')) {
            ch = ch - '0' + 52;
        } else if (ch == '+') {
            ch = 62;
        } else if (ch == '=') {
            flendtext = true;
        } else if (ch == '/') {
            ch = 63;
        } else {
            flignore = true;
        }
        
        if (!flignore) {
            short ctcharsinput = 3;
            Boolean flbreak = false;
            
            if (flendtext) {
                if (ixinput == 0) {
                    break;
                }
                
                if ((ixinput == 1) || (ixinput == 2)) {
                    ctcharsinput = 1;
                } else {
                    ctcharsinput = 2;
                }
                
                ixinput = 3;
                
                flbreak = true;
            }
            
            input[ixinput++] = ch;
            
            if (ixinput == 4) {
                ixinput = 0;
                
                unsigned char0 = input[0];
                unsigned char1 = input[1];
                unsigned char2 = input[2];
                unsigned char3 = input[3];
                
                output[0] = (char0 << 2) | ((char1 & 0x30) >> 4);
                output[1] = ((char1 & 0x0F) << 4) | ((char2 & 0x3C) >> 2);
                output[2] = ((char2 & 0x03) << 6) | (char3 & 0x3F);
                
                for (i = 0; i < ctcharsinput; i++) {
                    [result appendBytes: &output[i] length: 1];
                }
            }
            
            if (flbreak) {
                break;
            }
        }
    }
    
    return result;
}


@end

