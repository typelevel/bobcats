import cats.Show
import cats.syntax.all._
import sbt._
import scala.meta._
import scodec.bits._
import cats.parse.Parser

object AESGCMEncryptTestVectorGenerator extends TestVectorGenerator {

  import TestVectorGenerator._
  import AESGCMEncryptTestVectorParser._

  def generate(testDataFiles: Seq[File]): Source = {
    val result = testDataFiles
      .toList
      .flatTraverse { file => parser.parseAll(IO.read(file)).map(_.toList.map((file, _))) }
      .map { sections =>
        val testVectors = for {
          (file, Section(testVectors)) <- sections
          TestVector(count, key, iv, ad, plainText, cipherText, tag) <- testVectors.toList
        } yield {
          q"""
            TestVector(
                ${file.getName},
                $count,
                ${Term.Name("AESGCM" + key.length * 8L)},
                ${hexInterpolate(key)},
                new IV(${hexInterpolate(iv)}),
                ${hexInterpolate(plainText)},
                ${hexInterpolate(cipherText)},
                ${hexInterpolate(tag)},
                ${hexInterpolate(ad)})
            """
        }
        source"""
      package bobcats

      import scodec.bits._

      object AESGCMEncryptTestVectors {

        import BlockCipherAlgorithm._

        case class TestVector(
          file: String,
          count: Int,
          algorithm: AES.GCM,
          key: ByteVector,
          iv: IV,
          plainText: ByteVector,
          cipherText: ByteVector,
          tag: ByteVector,
          ad: ByteVector
        )

        def allTestVectors: Seq[TestVector] = Seq(..${testVectors})
      }
      """
      }
    result match {
      case Left(err) => throw new IllegalStateException(Show[Parser.Error].show(err))
      case Right(source) => source
    }
  }
}
