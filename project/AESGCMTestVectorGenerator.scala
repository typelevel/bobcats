import cats.Show
import cats.syntax.all._
import sbt._
import sbt.nio.file.FileTreeView
import scala.meta._
import scodec.bits._
import scodec.bits.Bases.Alphabets
import cats.parse.Parser
import org.scalafmt.sbt.ScalafmtPlugin

object AESGCMEncryptTestVectorGenerator extends TestVectorGenerator {

  import TestVectorGenerator._
  import AESGCMEncryptTestVectorParser._

  def generate(testDataFiles: Seq[File], targetDir: File): Source = {
    val result = testDataFiles.toList.flatTraverse { file =>
      val a = parser.parseAll(IO.read(file)).map(_.toList)
      // a match {
      //   case Right(sections) =>
      //     val content = sections.toList.take(50).map(s =>
      //       Section(cats.data.NonEmptyList(s.testVectors.head, Nil)).show
      //     ).mkString("\n")
      //     IO.write(new File("test.rsp"), content)
      // }
      // ???
      a
    }.map { sections =>
      val testVectors = for {
        Section(testVectors) <- sections
        TestVector(count, key, iv, ad, plainText, cipherText, tag) <- testVectors.toList
      } yield {
        val adTerm = if (ad.isEmpty) {
          q"None"
        } else {
          q"Some(${hexInterpolate(ad)})"
        }
          q"""
            TestVector(
                $count,
                AESGCM256,
                ${hexInterpolate(key)},
                ${hexInterpolate(iv)},
                ${hexInterpolate(plainText)},
                ${hexInterpolate(cipherText)},
                ${hexInterpolate(tag)},
                $adTerm)
            """
      }
      source"""
      package bobcats

      import scodec.bits._

      object AESGCMTestVectors {

        import BlockCipherAlgorithm._

        case class TestVector(
          count: Int,
          algorithm: AES.GCM,
          key: ByteVector,
          iv: ByteVector,
          plainText: ByteVector,
          cipherText: ByteVector,
          tag: ByteVector,
          ad: Option[ByteVector]
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
