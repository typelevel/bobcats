package bobcats

import cats.parse.{Numbers, Parser => P}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

// Parser for NIST .rsp Test Vector files
object AESTestVectorParser {
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

  private val whitespace = P.charIn(" \t\r\n").void
  private val whitespaces = whitespace.rep0.void
  private val nl = P.charIn("\r\n").rep.void

  private val comment = P.char('#') *> P.until(P.charIn("\r\n").rep)

  private val header = comment.repSep(P.charIn("\r\n").rep)

  private val hexString = P
    .charIn(('0' to '9') ++ ('a' to 'f') ++ ('A' to 'F'))
    .rep
    .string
    .map(ByteVector.fromValidHex(_))

  private def section(name: String, entryParser: P[TestVector]) =
    P.string(s"[$name]") *> entryParser.surroundedBy(whitespaces).rep

  private def assignment[A](name: String, valueParser: P[A]): P[A] =
    P.string(name) *> P.char('=').surroundedBy(whitespaces) *> valueParser

  private val encryptEntry = (
    (assignment("COUNT", Numbers.digits.map(_.toInt)) <* nl) ~
      (assignment("KEY", hexString) <* nl) ~
      (assignment("IV", hexString) <* nl) ~
      (assignment("PLAINTEXT", hexString) <* nl) ~
      (assignment("CIPHERTEXT", hexString))
  ).map {
    case ((((index, key), iv), plainText), cipherText) =>
      TestVector(index, key, iv, plainText, cipherText)
  }

  private val decryptEntry = (
    (assignment("COUNT", Numbers.digits.map(_.toInt)) <* nl) ~
      (assignment("KEY", hexString) <* nl) ~
      (assignment("IV", hexString) <* nl) ~
      (assignment("CIPHERTEXT", hexString) <* nl) ~
      (assignment("PLAINTEXT", hexString))
  ).map {
    case ((((index, key), iv), cipherText), plainText) =>
      TestVector(index, key, iv, plainText, cipherText)
  }

  private val encryptSection = section("ENCRYPT", encryptEntry)

  private val decryptSection = section("DECRYPT", decryptEntry)

  private val parser =
    header *> (encryptSection ~ decryptSection).surroundedBy(whitespaces).map(TestVectors.tupled)

  def parse(input: String) =
    parser.parseAll(input)
}
