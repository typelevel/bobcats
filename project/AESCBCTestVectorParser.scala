import cats.syntax.all._
import cats.parse.{Numbers, Parser => P}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

object AESCBCTestVectorParser {

  import ResponseFileParser._

  case class TestVectors(
      encrypt: NonEmptyList[TestVector],
      decrypt: NonEmptyList[TestVector]
  ) {
    def show: String =
      s"""
        |[ENCRYPT]
        |${encrypt.map(_.show).toList.mkString("\n")}
        |[DECRYPT]
        |${decrypt.map(_.show).toList.mkString("\n")}
      """.stripMargin
  }

  case class TestVector(
      index: Int,
      key: ByteVector,
      iv: ByteVector,
      plainText: ByteVector,
      cipherText: ByteVector) {
    def show: String =
      s"""
        |COUNT = ${index}
        |KEY = ${key.toHex}
        |IV = ${iv.toHex}
        |PLAINTEXT = ${plainText.toHex}
        |CIPHERTEXT = ${cipherText.toHex}
      """.stripMargin
  }

  private val entryL = 
    ((assignment("COUNT", Numbers.digits.map(_.toInt)) <* nl),
      (assignment("KEY", hexString) <* nl),
      (assignment("IV", hexString) <* nl)).mapN((_, _, _))

  private val encryptEntry = (
    entryL,
    (assignment("PLAINTEXT", hexString) <* nl),
    assignment("CIPHERTEXT", hexString)
  ).mapN {
    case ((count, key, iv), pt, ct) => TestVector(count, key, iv, pt, ct)
  }

  private val decryptEntry = (
    entryL,
    (assignment("CIPHERTEXT", hexString) <* nl),
    assignment("PLAINTEXT", hexString)
  ).mapN {
    case ((count, key, iv), ct, pt) => TestVector(count, key, iv, pt, ct)
  }


  private val encryptSection = section("ENCRYPT", encryptEntry)
  private val decryptSection = section("DECRYPT", decryptEntry)

  val parser =
    header *> (encryptSection ~ decryptSection)
      .surroundedBy(whitespaces)
      .map(TestVectors.tupled)
}
