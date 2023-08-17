import cats.syntax.all._
import sbt._
import scala.meta._
import scodec.bits._
import cats.parse.Parser

object AESCBCTestVectorGenerator extends TestVectorGenerator {

  import TestVectorGenerator._
  import AESCBCTestVectorParser._

  def generate(testFiles: Seq[File]): Source = {
    val result = testFiles
      .toList
      .flatTraverse { file =>
        val a = parser.parseAll(IO.read(file))

        // a.foreach {
        //   case TestVectors(e, d) =>
        //     val pp = TestVectors(cats.data.NonEmptyList(e.head, e.tail.take(16)), cats.data.NonEmptyList(d.head, d.tail.take(16))).show
        //     println(file)
        // }

        parser.parseAll(IO.read(file)).map {
          case TestVectors(encrypt, decrypt) =>
            encrypt.map {
              case TestVector(count, key, iv, pt, ct) =>
                q"""
              TestVector(
                true,
                ${file.getName},
                $count,
                ${Term.Name("AESCBC" + key.length * 8L)},
                ${hexInterpolate(key)},
                new IV(${hexInterpolate(iv)}),
                ${hexInterpolate(pt)},
                ${hexInterpolate(ct)},
              )
              """
            }.toList ++ decrypt.map {
              case TestVector(count, key, iv, pt, ct) =>
                q"""
              TestVector(
                false,
                ${file.getName},
                $count,
                ${Term.Name("AESCBC" + key.length * 8L)},
                ${hexInterpolate(key)},
                new IV(${hexInterpolate(iv)}),
                ${hexInterpolate(pt)},
                ${hexInterpolate(ct)},
              )
              """
            }.toList
        }
      }
      .map { testVectors =>
        // TODO: Create utility method....
        val vectorTerms = testVectors
          .grouped(128)
          .zipWithIndex
          .map {
            case (vectors, n) =>
              val termName = Term.Name("testVector" + n)
              (termName, q"private def $termName: Seq[TestVector] = Seq(..${vectors})")
          }
          .toList

        val defns = vectorTerms.map(_._2).toList
        val term = vectorTerms.foldLeft(q"Seq[TestVector]()") { (b, a) => q"${b}.++(${a._1})" }

        source"""
      package bobcats

      import scodec.bits._
      import BlockCipherAlgorithm._

      object AESCBCTestVectors {
        case class TestVector(
          encrypt: Boolean,
          file: String,
          count: Int,
          cbc: AES.CBC,
          key: ByteVector,
          iv: IV,
          plainText: ByteVector,
          cipherText: ByteVector
        )

        def allTestVectors: Seq[TestVector] = ${term}

        ..${defns}
      }
      """
      }

    result match {
      case Left(err) => throw new IllegalStateException(cats.Show[Parser.Error].show(err))
      case Right(source) => source
    }
  }
}
