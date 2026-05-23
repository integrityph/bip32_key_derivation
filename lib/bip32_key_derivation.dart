// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:boringssl_ffi/boringssl_ffi.dart' as bssl;
import 'package:secp256k1_ffi/secp256k1_ffi.dart';

class BIP32DerivationKey {
  List<int>? privateKey;
  List<int>? _publicKey;
  Bip32Depth? depth;
  Bip32KeyIndex? index;
  Bip32ChainCode? chainCode;
  Bip32FingerPrint? _fingerPrint;
  Bip32FingerPrint? parentFingerPrint;
  Bip32KeyNetVersions? keyNetVer;
  EllipticCurveTypes curveType = EllipticCurveTypes.secp256k1;

  BIP32DerivationKey({
    List<int>? publicKey,
    this.privateKey,
    this.chainCode,
    this.depth,
    this.index,
    Bip32FingerPrint? fingerPrint,
    Bip32KeyNetVersions? keyNetVer,
    this.parentFingerPrint,
  }) : _publicKey = publicKey,
       _fingerPrint = fingerPrint,
       keyNetVer = keyNetVer ?? defaultKeyNetVersion;

  BIP32DerivationKey.fromBip32Slip10Secp256k1(Bip32Slip10Secp256k1 key) {
    privateKey = key.privateKey.raw;
    _publicKey = key.publicKey.compressed;
    depth = key.depth;
    index = key.index;
    chainCode = key.chainCode;
    _fingerPrint = key.fingerPrint;
    keyNetVer = key.keyNetVersions;
  }

  BIP32DerivationKey.fromSeed({
    required List<int> seedBytes, // The 64-byte BIP39 seed
    required Bip32KeyNetVersions keyNetVersions,
    String hmacKeyString = "Bitcoin seed", // BIP32 standard for secp256k1
  }) {
    if (seedBytes.length < 16 || seedBytes.length > 64) {
      // BIP32 recommends 16-64 bytes
      throw ArgumentError(
        "Seed length must be between 16 and 64 bytes. got ${seedBytes.length}",
      );
    }
    
    final I = bssl.hmac.hmacSHA512(utf8.encode(hmacKeyString), seedBytes);
    if (I == null) {
      throw Exception(
        "Unable to derive HMAC from key:${hmacKeyString}, data:${hex.encode(seedBytes)}",
      );
      return;
    }

    final List<int> masterPrivateKeyBytes = I.sublist(0, 32);
    final List<int> masterChainCodeBytes = I.sublist(32);
    bool isZero = masterPrivateKeyBytes.every((byte) => byte == 0);
    // A full check against curve order N is more robust. libsecp256k1_ec_seckey_verify does this.
    // If you don't have an FFI for seckey_verify, this step is harder to do perfectly here.
    // Bip32PrivateKey.fromBytes in blockchain_utils does this check.
    if (isZero /* || masterPrivateKeyScalar >= N */ ) {
      throw ArgumentError(
        "Generated master private key is invalid (zero or >= N). Try a different seed or HMAC key.",
      );
    }

    privateKey = masterPrivateKeyBytes;
    chainCode = Bip32ChainCode(masterChainCodeBytes);
    depth = Bip32Depth(0);
    index = Bip32KeyIndex(0);
    parentFingerPrint = Bip32FingerPrint(Uint8List(4));
    keyNetVer = keyNetVersions;
  }

  BIP32DerivationKey.fromExtendedKey(
    String exKeyStr, [
    Bip32KeyNetVersions? keyNetVer,
  ]) {
    keyNetVer ??= defaultKeyNetVersion;
    final serKeyBytes = Base58Decoder.checkDecode(exKeyStr);
    bool isPublic =
        String.fromCharCodes(
          serKeyBytes.sublist(0, Bip32KeyNetVersions.length),
        ) ==
        String.fromCharCodes(keyNetVer.public);

    final depthIdx = Bip32KeyNetVersions.length;
    final fprintIdx = depthIdx + Bip32Depth.fixedLength();
    final keyIndexIdx = fprintIdx + Bip32FingerPrint.fixedLength();
    final chainCodeIdx = keyIndexIdx + Bip32KeyIndex.fixedLength();
    final keyIdx = chainCodeIdx + Bip32ChainCode.fixedLength();

    // Get parts
    final depth = serKeyBytes[depthIdx];
    final fprintBytes = serKeyBytes.sublist(fprintIdx, keyIndexIdx);
    final keyIndexBytes = serKeyBytes.sublist(keyIndexIdx, chainCodeIdx);
    final chainCodeBytes = serKeyBytes.sublist(chainCodeIdx, keyIdx);
    var keyBytes = serKeyBytes.sublist(keyIdx);

    if (!isPublic) {
      if (keyBytes[0] != 0) {
        throw Exception(
          'Invalid extended private key (wrong secret: ${keyBytes[0]})',
        );
      }
      keyBytes = keyBytes.sublist(1);
      privateKey = keyBytes;
    } else {
      _publicKey = keyBytes;
    }
    this.depth = Bip32Depth(depth);
    _fingerPrint = Bip32FingerPrint(fprintBytes);
    index = Bip32KeyIndex(IntUtils.fromBytes(keyIndexBytes));
    chainCode = Bip32ChainCode(chainCodeBytes);
  }

  static Bip32KeyNetVersions get defaultKeyNetVersion {
    return Bip32KeyNetVersions(
      [0x04, 0x35, 0x87, 0xCF],
      [0x04, 0x35, 0x83, 0x94],
    );
  }

  Bip32KeyData getBip32KeyData() {
    return Bip32KeyData(
      chainCode: chainCode,
      depth: depth,
      index: index,
      fingerPrint: parentFingerPrint,
    );
  }

  Bip32Slip10Secp256k1 toBip32Slip10Secp256k1() {
    if (privateKey != null) {
      return Bip32Slip10Secp256k1.fromPrivateKey(
        privateKey!,
        keyData: getBip32KeyData(),
        keyNetVer: keyNetVer,
      );
    } else {
      return Bip32Slip10Secp256k1.fromPublicKey(
        publicKey,
        keyData: getBip32KeyData(),
        keyNetVer: keyNetVer,
      );
    }
  }

  List<int> get publicKey {
    if (_publicKey != null) {
      return _publicKey!;
    }
    _publicKey = secp256k1FFI.privateKey.createPubKey(
      privateKey!,
      isCompressed: true,
    );
    return _publicKey!;
  }

  set publicKey(List<int>? val) {
    _publicKey == val;
  }

  Bip32FingerPrint get fingerPrint {
    _fingerPrint ??= Bip32FingerPrint(QuickCrypto.hash160(publicKey));
    return _fingerPrint!;
  }

  set fingerPrint(Bip32FingerPrint? val) {
    _fingerPrint == val;
  }

  String get extendedPrivateKey {
    final List<int> serKey = List<int>.from([
      ...keyNetVer!.private,
      ...depth!.toBytes(),
      ...parentFingerPrint!.toBytes(),
      ...index!.toBytes(),
      ...chainCode!.toBytes(),
      ...[0x00, ...privateKey!],
    ]);
    return Base58Encoder.checkEncode(serKey);
  }

  String get extendedPublicKey {
    final List<int> serKey = List<int>.from([
      ...keyNetVer!.public,
      ...depth!.toBytes(),
      ...parentFingerPrint!.toBytes(),
      ...index!.toBytes(),
      ...chainCode!.toBytes(),
      ...publicKey,
    ]);
    return Base58Encoder.checkEncode(serKey);
  }

  BIP32DerivationKey? derivePath(String path) {
    final pathInstance = Bip32PathParser.parse(path);
    BIP32DerivationKey? key = this;
    for (final pathElement in pathInstance.elems) {
      key = key?.childKey(pathElement);
    }
    return key;
  }

  BIP32DerivationKey? childKey(Bip32KeyIndex index) {
    BIP32DerivationKey key = this;
    final isPublic = key.privateKey == null;

    if (!isPublic) {
      final result = ckdPriv(key, index, key.curveType);
      return BIP32DerivationKey(
        chainCode: Bip32ChainCode(result.$2),
        depth: key.depth!.increase(),
        index: index,
        parentFingerPrint: key.parentFingerPrint,
        keyNetVer: key.keyNetVer,
        privateKey: result.$1,
      );
    }

    if (index.isHardened) {
      print(
        "Public child derivation cannot be used to create an hardened child key",
      );
      return null;
    }
    final result = ckdPub(key, index, key.curveType);
    if (result == null) {
      return null;
    }
    BIP32DerivationKey newKey = BIP32DerivationKey(
      chainCode: Bip32ChainCode(result.$2),
      depth: key.depth!.increase(),
      index: index,
      parentFingerPrint: key.fingerPrint,
      keyNetVer: key.keyNetVer,
      publicKey: result.$1,
    );
    return newKey;
  }

  List<int>? signMessage(
    List<int> message, {
    String messagePrefix = '\x18Bitcoin Signed Message:\n',
  }) {
    final fullMsg = utf8.encode(messagePrefix) + Uint8List.fromList(message);
    final digest = bssl.sha256.hash(bssl.sha256.hash(fullMsg)!);
    final sig = secp256k1FFI.ecdsa.sign(
      digest!,
      Uint8List.fromList(privateKey!),
      isDER: false,
    );

    return sig;
  }

  // static BigInt _bytesToBigInt(Uint8List bytes) {
  //   if (bytes.length > 32) {
  //     throw ArgumentError("Bytes length exceeds 32 for BigInt conversion.");
  //   }
  //   BigInt result = BigInt.zero;
  //   for (int i = 0; i < bytes.length; i++) {
  //     result = (result << 8) | BigInt.from(bytes[i]);
  //   }
  //   return result;
  // }

  // Uint8List _bigIntTo32Bytes(BigInt value) {
  //   final bytes = Uint8List(32);
  //   if (value < BigInt.zero) {
  //       throw ArgumentError("Cannot convert negative BigInt to fixed-size unsigned bytes.");
  //   }
  //   for (int i = 0; i < 32; i++) {
  //     bytes[31 - i] = (value & BigInt.from(0xFF)).toInt();
  //     value = value >> 8;
  //   }
  //   if (value != BigInt.zero) {
  //       // This should not happen if the BigInt fits in 32 bytes (N and S values do)
  //       throw StateError("BigInt value too large for 32 bytes.");
  //   }
  //   return bytes;
  // }

  (List<int>, List<int>) ckdPriv(
    BIP32DerivationKey key,
    Bip32KeyIndex index,
    EllipticCurveTypes type,
  ) {
    List<int> dataBytes;
    if (index.isHardened) {
      dataBytes = List<int>.from([
        ...Bip32Slip10DerivatorConst.priveKeyPrefix,
        ...key.privateKey!,
        ...index.toBytes(),
      ]);
    } else {
      dataBytes = List<int>.from([...key.publicKey, ...index.toBytes()]);
    }
    final hmacHalves = bssl.hmac.hmacSHA512(key.chainCode!.toBytes(), dataBytes);
    if (hmacHalves == null) {
      return ([],[]);
    }

    final ilBytes = hmacHalves.sublist(0, 32);
    final irBytes = hmacHalves.sublist(32, 64);
    final scalar = secp256k1FFI.privateKey.tweakAdd(
      key.privateKey!,
      ilBytes,
    );

    return (scalar!, irBytes);
  }

  (List<int>, List<int>)? ckdPub(
    BIP32DerivationKey pubKey,
    Bip32KeyIndex index,
    EllipticCurveTypes type,
  ) {
    final dataBytes = List<int>.from([...publicKey, ...index.toBytes()]);
    final hmacHalves = bssl.hmac.hmacSHA512(pubKey.chainCode!.toBytes(), dataBytes);
    if (hmacHalves == null) {
      return ([],[]);
    }

    final ilBytes = hmacHalves.sublist(0, 32);
    final irBytes = hmacHalves.sublist(32, 64);

    final newPubKeyPoint = secp256k1FFI.publicKey.tweakAdd(
      pubKey.publicKey,
      ilBytes,
    );
    if (newPubKeyPoint == null) {
      print("unable to perform public key scalar addition");
      return null;
    }
    return (newPubKeyPoint, irBytes);
  }
}
