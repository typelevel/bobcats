package bobcats

import cats.effect.IO
import cats.syntax.all._
import munit.CatsEffectSuite
import cats.effect.kernel.Async

class AESCBCSuite extends CatsEffectSuite {

  import CipherAlgorithm._

  def cbcTestVectorsNoPadding[F[_]: Async](dataName: String) = {
    val cipher = Cipher[F]

    val dataFile = getClass().getResourceAsStream(s"/CBC${dataName}256.rsp")

    val testCases = AESTestVectorParser
      .parse(new String(dataFile.readAllBytes(), "UTF-8"))
      .leftMap(_.show)
      .getOrElse(fail(s"Unable to parse $dataName test data file"))

    for (testCase <- testCases.encrypt) yield {
      test(s"AESVS $dataName test data for CBC - encrypt test case ${testCase.index} - No Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.None))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.None))
          obtained <- cipher.encrypt(key, iv, testCase.plainText)
          expected = testCase.cipherText
        } yield assertEquals(obtained, expected)
      }
    }

    for (testCase <- testCases.decrypt) yield {
      test(s"AESVS $dataName test data for CBC - decrypt test case ${testCase.index} - No Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.None))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.None))
          obtained <- cipher.decrypt(key, iv, testCase.cipherText)
          expected = testCase.plainText
        } yield assertEquals(obtained, expected)
      }
    }
  }

  def cbcTestVectorsPKCS7Padding[F[_]: Async](dataName: String) = {
    val cipher = Cipher[F]

    val dataFile = getClass().getResourceAsStream(s"/CBC${dataName}256.rsp")

    val testCases = AESTestVectorParser
      .parse(new String(dataFile.readAllBytes(), "UTF-8"))
      .leftMap(_.show)
      .getOrElse(fail(s"Unable to parse $dataName test data file"))

    // There's no point in trying the decrypt cases - they're not padded so they won't work.
    // Instead we round-trip the encryption test cases.
    for (testCase <- testCases.encrypt) yield {
      test(
        s"AESVS $dataName test data for CBC - test case ${testCase.index} - PKCS#7 Padding") {
        for {
          key <- cipher.importKey(testCase.key, AESCBC256(PaddingMode.PKCS7))
          iv <- cipher.importIv(testCase.iv, AESCBC256(PaddingMode.PKCS7))
          cipherText <- cipher.encrypt(key, iv, testCase.plainText)
          expected = testCase.cipherText
          plainText <- cipher.decrypt(key, iv, cipherText)
        } yield {
          assertEquals(cipherText.take(expected.length), expected)
          assertEquals(plainText, testCase.plainText)
        }
      }
    }
  }

  // Browser SubtleCrypto cannot disable padding
  if (Set("JVM", "NodeJS").contains(BuildInfo.runtime)) {
    cbcTestVectorsNoPadding[IO]("GFSbox")
    cbcTestVectorsNoPadding[IO]("KeySbox")
    cbcTestVectorsNoPadding[IO]("VarKey")
    cbcTestVectorsNoPadding[IO]("VarTxt")
  }

  cbcTestVectorsPKCS7Padding[IO]("GFSbox")
  cbcTestVectorsPKCS7Padding[IO]("KeySbox")
  cbcTestVectorsPKCS7Padding[IO]("VarKey")
  cbcTestVectorsPKCS7Padding[IO]("VarTxt")
}
