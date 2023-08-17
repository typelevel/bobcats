import cats.syntax.all._
import cats.parse.{Numbers, Parser => P, Parser0 => P0}
import scodec.bits.ByteVector
import cats.data.NonEmptyList

object ResponseFileParser {

  val whitespace0 = P.charIn(" \t\r").void
  val whitespaces0 = whitespace0.rep0.void

  val whitespace = P.charIn(" \t\r\n").void
  val whitespaces = whitespace.rep0.void
  val nl = P.charIn("\r\n").rep.void
  val comment = P.char('#') *> P.until(P.charIn("\r\n").rep)
  val header = comment.repSep(P.charIn("\r\n").rep)
  val hexString = P
    .charIn(('0' to '9') ++ ('a' to 'f') ++ ('A' to 'F'))
    .rep0
    .string
    .map(ByteVector.fromValidHex(_))

  def sectionParam[A](name: String, valueParser: P[A]) =
    P.char('[') *> assignment(name, valueParser) <* P.char(']')

  def section[A](name: String, bodyParser: P[A]) =
    P.string(s"[$name]") *> bodyParser.surroundedBy(whitespaces).rep

  def assignment[A](name: String, valueParser: P0[A]): P[A] =
    P.string(name) *> P.char('=').surroundedBy(whitespaces0) *> valueParser
}
