

#import <CommonCrypto/CommonCryptor.h>
#import <Foundation/Foundation.h>

#define FBENCRYPT_ALGORITHM     kCCAlgorithm3DES
#define FBENCRYPT_BLOCK_SIZE    64
#define FBENCRYPT_KEY_SIZE      kCCKeySize3DES//kCCKeySize3DES

@interface HighQEncryptor : NSObject {
    
}

//-----------------
// API (raw data)
//-----------------
+ (NSData*)encryptData:(NSData*)data key:(NSData*)key iv:(NSData*)iv;
+ (NSData*)decryptData:(NSData*)data key:(NSData*)key iv:(NSData*)iv;


//-----------------
// API (base64)
//-----------------
// the return value of encrypteMessage: and 'encryptedMessage' are encoded with base64.
//
+ (NSString*)encryptBase64String:(NSString*)string;
+ (NSString*)decryptBase64String:(NSString*)encryptedBase64String;


@end
