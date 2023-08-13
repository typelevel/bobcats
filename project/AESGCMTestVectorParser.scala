import cats.syntax.all._
import cats.parse.{Numbers, Parser => P}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

object AESGCMEncryptTestVectorParser {

  import ResponseFileParser._

  case class TestVector(
      index: Int,
      key: ByteVector,
      iv: ByteVector,
      ad: ByteVector,
      plainText: ByteVector,
      cipherText: ByteVector,
      tag: ByteVector)

  case class Section(
    keyLength: Int,
    tagLength: Int,
    testVectors: NonEmptyList[TestVector]
  )

  private val sectionHeader = 
    (sectionParam("Keylen", Numbers.digits.map(_.toInt)) <* nl) ~
  (sectionParam("IVlen", Numbers.digits.void) *> nl *>
    sectionParam("PTlen", Numbers.digits.void) *> nl *>
    sectionParam("AADlen", Numbers.digits.void) *> nl *>
    sectionParam("Taglen", Numbers.digits.map(_.toInt)))

  private val entry = (
    assignment("Count", Numbers.digits.map(_.toInt)) <* nl,
    assignment("Key", hexString) <* nl,
    assignment("IV", hexString) <* nl,
    assignment("PT", hexString) <* nl,
    assignment("AAD", hexString) <* nl,
    assignment("CT", hexString) <* nl,
    assignment("Tag", hexString)
  ).mapN(TestVector.apply)

  private val section =
    (sectionHeader ~ entry.surroundedBy(whitespaces).rep).map {
      case ((keyLength, tagLength), entries) => Section(keyLength, tagLength, entries)
    }.surroundedBy(whitespaces)

  val parser: P[NonEmptyList[Section]] = header *> section.rep

}
