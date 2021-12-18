from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode
import os
from shutil import copyfile


def encryptAESKey(AESKey, pemPbc):
    from .UserOnboarding import decodeStringToBytes
    publicKey = serialization.load_pem_public_key(
        decodeStringToBytes(pemPbc),
        backend=default_backend()
    )

    encryptedAESKey = publicKey.encrypt(
        AESKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    from .UserOnboarding import encodeBytesToString
    return encodeBytesToString(encryptedAESKey)


def decryptAESKey(encryptedAESKey, pemPvt):
    privateKeyBytes = b64decode(pemPvt)
    privateKey = serialization.load_pem_private_key(
        privateKeyBytes,
        password=None,
        backend=default_backend()
    )

    decryptedAESKey = privateKey.decrypt(
        b64decode(encryptedAESKey),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    from .UserOnboarding import encodeBytesToString
    return encodeBytesToString(decryptedAESKey)


def encryptSharedAESKey(AESKey, user1_PemPvt, user2_PemPbc):
    print("Encrypting Shared Key")
    AESKey = b64decode(AESKey)
    user1_PemPvt = b64decode(user1_PemPvt)
    user2_PemPbc = b64decode(user2_PemPbc)
    publicKey = serialization.load_pem_public_key(
        user2_PemPbc,
        backend=default_backend()
    )

    privateKey = serialization.load_pem_private_key(
        user1_PemPvt,
        password=None,
        backend=default_backend()
    )

    encryptedSharedAESKey = publicKey.encrypt(
        AESKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    signature = privateKey.sign(
        encryptedSharedAESKey,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # encryptionLv1 = encryptAESKey(AESKey,user1_PemPvt)
    # encryptedSharedAESKey = encryptAESKey(encryptionLv1,user2_PemPbc)
    from .UserOnboarding import encodeBytesToString
    return encodeBytesToString(encryptedSharedAESKey), encodeBytesToString(signature)


def decryptSharedAESKey(encryptedSharedAESKey, user1_PemPbc, user2_PemPvt, signature):
    print("Decrypting Shared Key")
    encryptedSharedAESKey = b64decode(encryptedSharedAESKey)
    user1_PemPbc = b64decode(user1_PemPbc)
    user2_PemPvt = b64decode(user2_PemPvt)
    signature = b64decode(signature)
    public_key = serialization.load_pem_public_key(
        user1_PemPbc,
        backend=default_backend()
    )

    try:
        public_key.verify(
            signature,
            encryptedSharedAESKey,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        return None,False

    privateKey = serialization.load_pem_private_key(
        user2_PemPvt,
        password=None,
        backend=default_backend()
    )

    decryptedSharedAESKey = privateKey.decrypt(
        encryptedSharedAESKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    from .UserOnboarding import encodeBytesToString
    return encodeBytesToString(decryptedSharedAESKey),True

# if __name__ == "__main__":
#     key = b"NarayanaMurari"
#     user1_PemPvt = b64decode("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRREdpb1Q5Si8waDNtUkkKM0NLWm5lQ3VFeVN4Q25TbjBkZUJQVDFFN3FxTUZKMEhWMTdYSjExZkJTZWVkQlhTQUVRWVpQSTFrNTRKM1pwVAp4SkYwTVZhay90VDJnd1VLMXVzUHhSbUpqK1FobFBIZG12b29hWHVwL2pmbTBUWjJ3SVVENFdGMUhYcVVWNVFSCjRteE42aU9KS0RDWXJKY1ZSbENQaWRveEJmVE9xMWxxRlRPQ2xsNjVtMmc5U1ZmRzIzSmR5ZUMyUFBzZ3Y0VlUKaFhGcHpnVHFRdUFTL0dVa2JzSitpZFlEaTNxbEUvMEZZM0Y3SmdCTVFJY2FxYkc1OU1pcjl2WXVIa2JjckovWgpINU5KUWIvMkN0TzN2dGtWV3FzTSttZENoSklmdGd0R0JIb1NzVkVDWWFoRTU2SXdxNWdrK2c0TDZ4VnJGMTJtCkRtU0h6SXFSQWdNQkFBRUNnZ0VBVkxRVU9NMHV1WnhmdkpYdVRRdUdKNzRURVZVY245eHV6THlMdnpUem5mL04KWHF4djBlc0JjdUNJSHBuNEZUZjMxVkI3NVUrdFJSZytGeTd0djF5dFVvZEY1RVhSaU9aWU1zb3NNdndvb0FzagpoUi94U2Z4MnZmZXZjZElnSWxuUVplOXAzTVZPM3FyZWlTTElnaFU2US9IWmljbFlTOE5MNjNFc25XMmxHK1pOCkhUcmpsRXBWazg0bUF0Nmd5cytod3IyWVdLanpUbk1WUFVzVzB4N2liVHJoUTZCbXo1MXF6dFUySlFTSzJGKzYKdzRXcU1KSjd6T2pGU25WYWpweUhGeGhGWmF0SXI3cmIvMUo4Mmc5WkplM1JFd3o5MFlDaEZPSExybXNuZVdhdApIWlRmNUl5ZUNaYU9EMkowK0JJVWtLSEFtUTl4eGtKMm9ua1ZkTzFNZ1FLQmdRRDd2cjJDaXBROVhFeTRYT1pqCmo3UStwUmpsRlRCVVppSVBFZUY4SWZaVHFGZDAzNy84bmdKVnROV0sxUTRQNkhSWFpVQy8vLzJySHNmTkZPOWoKV0NZRDAwdjFzUys4VCtUbGxsVXk5Z1F2Y2grcDMzcmdsMDFnSHdhSTRWUGFsL1Vpb1g3aFZidzNhR3pDKzUrSQo1MDdUZHRxRUNqTEY0OGNQYWt6NlJvRG9MUUtCZ1FESjVaTURyRGRkT1lkS2ExNG95MEYwdmxaWTlsN3g5YXJWCkhNUzhQTHJhK0l6ZXVhRS9idDlUL2NoMjQ5Tjc1NnRwUFdUYlVsRGZMblNJQ2J0dXBkenRQdTFsY1NINTI4Z2kKQ0ZwWHRxd1F5KzRzL0lwdFF6K1hEbks2YWNWYStod2RqOFpNRzdMSmp1MXRlT05GTmtEa1RGcHJONDUxMjZmdwpJM0NmcTdMbWRRS0JnRm5hMndtZExRdzV4YWlJZ0ROSk42eWtnUjVEVWR6T0Y1b0paOUpHelFWUE1PZ21kUUJWCjViOXhyRWJCaFNOb2RSNDhwYi9pUDBpMDA5di9mUEtZby9qNWtrTS8yeW43MmxlWU1SRGZmdDd3ZlJ6RkI3YmkKU2x2a3R4QmtYT25KRTFZcERvQ2ZlVzdOZHdTaGkyL3lIOUNhdTZRbGY3bmljMHF0Um95T1hiU0JBb0dCQUtjRwpGbVplYlhyaEljeHVJSHB0RkJ5SmJoT3cxZ0VqZEkxVGZHb2hiNC9CT1lEMFhyS0VmWnNWZzJiZnVWQnk2cnBvCmdPeDBIOVZTc0RMdW9qRzZZNWVkakhWMGIyQXQ4MVk4Uk1qMXBVbEwvQ0VaVjBkbTc4OStzMmtHSWEvTzQ3Mk0KK01aeno2ZXhaemcrWHY0ZUVQY05OMndsak9SeHNIQVlVWTYyVTQwVkFvR0JBSVA4YUwwNlRuTU54aEs1clFuUApRTTcxYm5ocEo5TWdFd2twTHNXUUg5LytveXFuVTFpNWR5M2pWaEVlb0JHemJjVDl0S216WE03Q0tsNExTU0J2CmR0STg0NU93NXYrVTlyNXlQWmxZRE5IL3IySDRCOVVZSE1oank0SWt4d2NWM3dOMWxWVy90U0U1dW9rdEllSGoKTVRBbzRlS2RZYWFUSFZXRTlyQVVMSGwxCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K")
#     user1_PemPbc = b64decode("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4b3FFL1NmOUlkNWtTTndpbVozZwpyaE1rc1FwMHA5SFhnVDA5Uk82cWpCU2RCMWRlMXlkZFh3VW5ublFWMGdCRUdHVHlOWk9lQ2QyYVU4U1JkREZXCnBQN1U5b01GQ3RickQ4VVppWS9rSVpUeDNacjZLR2w3cWY0MzV0RTJkc0NGQStGaGRSMTZsRmVVRWVKc1Rlb2oKaVNnd21LeVhGVVpRajRuYU1RWDB6cXRaYWhVemdwWmV1WnRvUFVsWHh0dHlYY25ndGp6N0lMK0ZWSVZ4YWM0RQo2a0xnRXZ4bEpHN0Nmb25XQTR0NnBSUDlCV054ZXlZQVRFQ0hHcW14dWZUSXEvYjJMaDVHM0t5ZjJSK1RTVUcvCjlnclR0NzdaRlZxckRQcG5Rb1NTSDdZTFJnUjZFckZSQW1Hb1JPZWlNS3VZSlBvT0Mrc1ZheGRkcGc1a2g4eUsKa1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==")

#     user2_PemPbc = b64decode("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE1UGlLYlZZTFo5bThQdzE1RjBicQpCdW95VjBBbkNIamhKNW54aWdQSEhLOFFrSjk0bCttZ3JlaTg3V2l6M2FZZFpnWTByNWJKT3NLV3J2OGZmcUNPClIzYitYejcvQjQ3TDByTmE1RHFWMUhTQ21EUXU5VTdqRXYxS0d4aEJqR2JQd1ZvVmR1WlNQOTNFNTBiNHhwK2YKeGNnY2htLzJBckZUbHZQaEdXaUNkWmRsVDU2Rmo5Vi9Ba1U1bVNRdjNKU0FDSWVOZzFueHR0Y1FqSFdraU1EKwp5ZC9NbVRzemZPSnV2aWtVMXRTeTRDVlNDNkRhNklZalE0U2tpbFpENSswc1FIeE8vWFBxS3FaQlZHa3JZb2tDCjhTVW9oM1RTSHV5UjB6SkkybFU3K2tUdEFMamdkemdub1J4WE53VGV3WWpsQklpQ2FVTXZublVSdVhQSnJMUFMKQVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==")
#     user2_PemPvt = b64decode("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRRGsrSXB0Vmd0bjJidy8KRFhrWFJ1b0c2akpYUUNjSWVPRW5tZkdLQThjY3J4Q1FuM2lYNmFDdDZMenRhTFBkcGgxbUJqU3Zsc2s2d3BhdQoveDkrb0k1SGR2NWZQdjhIanN2U3MxcmtPcFhVZElLWU5DNzFUdU1TL1VvYkdFR01acy9CV2hWMjVsSS8zY1RuClJ2akduNS9GeUJ5R2IvWUNzVk9XOCtFWmFJSjFsMlZQbm9XUDFYOENSVG1aSkMvY2xJQUloNDJEV2ZHMjF4Q00KZGFTSXdQN0ozOHlaT3pOODRtNitLUlRXMUxMZ0pWSUxvTnJvaGlORGhLU0tWa1BuN1N4QWZFNzljK29xcGtGVQphU3RpaVFMeEpTaUhkTkllN0pIVE1ramFWVHY2Uk8wQXVPQjNPQ2VoSEZjM0JON0JpT1VFaUlKcFF5K2VkUkc1CmM4bXNzOUlCQWdNQkFBRUNnZ0VBWUcyTFhxQnVEVDVWV1BpRGxwbjIxUktzUUxKenZjMnFoTk1BTmUrQlcwTWUKNXNsQ01EZmp3MW5RdHVyeFZOY3dhbGNTdVIvM2Z4ZVQvZjdUZExDSk91K1NFT3FtM0xmMmZyV3FBWlBxcFo2cgpvUTNZK05aUUt4OGdwbWlBc25CWjdrUFI1bEQ1TW94aThFT2pZWUszOXNOZnYvNUd6THVCU0lGTXV6YVlPb3pMCjNycUFydlExUFJrNXRlY2ZpbTMyZjZPQXJxRXpCQ3NjM1YrS3ZtaTIvMWhJNW5iZzNFVUxyckNQa0pxSnM0SDcKSmpuTmZTZnA3ZE55Rk0ybFNnVzRYT3NYZUZYeFM4eWcrMm5sYllRMm0vWkIwbktjVmplM09mK2RRbzVZVFRxTAo0M05YZk5zLytybjlUMEdkQzVIRzVPL1BReGZDT25qcG1wQ3JGYUNEUVFLQmdRRDBjd2tpbDg2R0VPdXpkWk5TCm1JNFEvZUo2d0JvZVR5QWRQK1R4bVdTRXZhNHhKOVlncnZRSWJZMlNJZ0lpWmI4N1ViSjlrRkhGbWJRb2xGaE0Kbm9oalhMVVA1K2ExRVVoTVRKT25CcmIxSm03RUhpVENwWENaQXg5bzJ2ZGVreXo2NGVVaTcyRkFHRDd4K3V1UApPWUdsaGpObVgzRGZFMmxZZTN5TkJrb0J0d0tCZ1FEdnlrVkF2M0J6TjQ5VkJsSjd2NnVaemdDaS9rd2cwcnVLCm1DTVpwcHc5dUZubHFFNllveUsya1Zqa2ZyV0hsNGJBSVN6MUdXRDRaYmh4ZnZrZmxQcUJDWEQ3WVIwNFdRMW4KRkg3OUY1emk1cVJPcWRRQkpVenpkRXVscDJjZEhCOUlFT0pVd1JsRmE0bFN2eWF6bFQ5U2sxZ0o1K3QraHp0NAo4emp0bzhocUJ3S0JnUURpRDR3d0tKRitIQ0hOS1h0ZmsrTTF4WVJ2bmozSkw4VjBKMFdUUkJiWVJ3M1RPWkxsClVNWXZFUmt1UGpNWkdsMFovM2lBZERtYThvVFFUamZHUzRtMzBlRkQzMkxVcWpIaEZhUXFmNlFzM0NqdFJ5OFoKcnFPTmJYemJuRHZOZzIvQ1o2dGVmbC9DUlduWW9BSzl4aUdtTUpCU0tRc1owVHJIOEJNRDNBQU95d0tCZ1FEZAowRzVmaHJldTNTWnBzSDk4bWNGVGRZeUJPbHVSd1Y1YXhvRXhxVDIrbWxvT1o3TE0zNXVzNXFja04xSVZLOFlxCjFJV1I5UGdPejRuZTgyWGdJUi9aWGJKMTExQUFYK0JXQ2srdUw3bWc2MW55cW9iQ3lJNTJabzNUbnhkemhpQXAKdWZTa0Vqd2VTMnVzYjhhTk9QSnFvSUpBSjVsZ1loaFJ1aXhmSjdLczRRS0JnUUNaMmZYVFpMR0xRVStieGJUSQpzUTBvOGtTaXpvMVYwSld5YjRaMEpOT3VnWUlncTc2a0N1UkJnbC9Vb1BDbmxRMlAzaDUxSGdFdWlONnRsaW1HClloZmRpQ1pIeVB6TkVNaGFrRzVXVjFockc2UFRLdVRPUlBteEJHK1Bzbm1hdG9OZk9rSHVkUHNGSmJnNTMzR04KSk5sY09HRzQrald2bjR0VXdkUEVGU2NEU3c9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==")

#     print(key)
#     encryptedSharedAESKey,signature = encryptSharedAESKey(key,user1_PemPvt,user2_PemPbc)
#     print(encryptedSharedAESKey)
#     decryptedSharedAESKey = decryptSharedAESKey(encryptedSharedAESKey,user1_PemPbc,user2_PemPvt,signature,encryptedSharedAESKey)
#     print(decryptedSharedAESKey)
