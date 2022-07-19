package bobcats

private[bobcats] trait AlgorithmPlatform
private[bobcats] trait HashAlgorithmPlatform
private[bobcats] trait HmacAlgorithmPlatform
private[bobcats] trait CipherAlgorithmPlatform

private[bobcats] trait AlgorithmParameterSpecPlatform[+A <: Algorithm]

private[bobcats] trait IvParameterSpecPlatform[+A <: CipherAlgorithm]
