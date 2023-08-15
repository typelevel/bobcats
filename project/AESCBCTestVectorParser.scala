import cats.syntax.all._
import cats.parse.{Numbers, Parser => P}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

object AESCBCTestVectorParser {

  import ResponseFileParser._

  case class TestVectors(
      encrypt: NonEmptyList[TestVector],
      decrypt: NonEmptyList[TestVector]
  )

  case class TestVector(
      index: Int,
      key: ByteVector,
      iv: ByteVector,
      plainText: ByteVector,
      cipherText: ByteVector)

  private val encryptEntry = (
    (assignment("COUNT", Numbers.digits.map(_.toInt)) <* nl),
    (assignment("KEY", hexString) <* nl),
    (assignment("IV", hexString) <* nl),
    (assignment("PLAINTEXT", hexString) <* nl),
    assignment("CIPHERTEXT", hexString)
  ).mapN(TestVector.apply)

  private val decryptEntry = (
    (assignment("COUNT", Numbers.digits.map(_.toInt)) <* nl),
    (assignment("KEY", hexString) <* nl),
    (assignment("IV", hexString) <* nl),
    (assignment("CIPHERTEXT", hexString) <* nl),
    assignment("PLAINTEXT", hexString)
  ).mapN(TestVector.apply)

  private val encryptSection = section("ENCRYPT", encryptEntry)

  private val decryptSection = section("DECRYPT", decryptEntry)

  val parser =
    header *> (encryptSection ~ decryptSection)
      .surroundedBy(whitespaces)
      .map(TestVectors.tupled)
}
