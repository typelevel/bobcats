import cats.syntax.all._
import sbt._
import sbt.nio.file.FileTreeView
import scala.meta._
import scodec.bits._
import scodec.bits.Bases.Alphabets
import cats.parse.Parser
import org.scalafmt.interfaces.Scalafmt

object AESCBCTestVectorGenerator {
  def hexInterpolate(data: ByteVector): Term =
    Term.Interpolate(
      Term.Name("hex"),
      List(Lit.String(data.toHex(Alphabets.HexLowercase))),
      List.empty)

  def generate(testDataFiles: Set[File], targetDir: File, scalafmtConfig: File): Set[File] = {
    val testFileNameMatcher = """CBC(\w+)256.rsp""".r

    val resultFile = testDataFiles
      .toList
      .traverse { testDataFile =>
        val testFileNameMatcher(dataType) = testDataFile.name

        AESCBCTestVectorParser.parse(IO.read(testDataFile)).map { testVectors =>
          val encryptVectors = testVectors.encrypt.map { encryptVector =>
            q"""
            TestVector(
                ${encryptVector.index},
                ${hexInterpolate(encryptVector.key)},
                ${hexInterpolate(encryptVector.iv)},
                ${hexInterpolate(encryptVector.plainText)},
                ${hexInterpolate(encryptVector.cipherText)})
            """
          }

          val decryptVectors = testVectors.encrypt.map { decryptVector =>
            q"""
            TestVector(
                ${decryptVector.index},
                ${hexInterpolate(decryptVector.key)},
                ${hexInterpolate(decryptVector.iv)},
                ${hexInterpolate(decryptVector.plainText)},
                ${hexInterpolate(decryptVector.cipherText)})
            """
          }

          val variableName =
            Character.toLowerCase(dataType.charAt(0)) + dataType.substring(1) + "TestVectors"

          q"""
          lazy val ${Pat.Var(Term.Name(variableName))} = TestVectors(
              dataType = ${Lit.String(dataType)},
              encrypt = NonEmptyList.of(..${encryptVectors.toList}),
              decrypt = NonEmptyList.of(..${decryptVectors.toList})
          )
          """
        }
      }
      .map { testVectorDeclarations =>
        val testVectorDeclarationNames =
          testVectorDeclarations.collect { case Defn.Val(_, List(Pat.Var(name)), _, _) => name }

        val allTestVectors =
          q"lazy val allTestVectors = List(..${testVectorDeclarationNames})"

        val result = source"""
        package bobcats

        import cats.data.NonEmptyList
        import scodec.bits._

        object AESCBCTestVectors {
            case class TestVectors(
                dataType: String,
                encrypt: NonEmptyList[TestVector],
                decrypt: NonEmptyList[TestVector]
            )

            case class TestVector(
                index: Int,
                key: ByteVector,
                iv: ByteVector,
                plainText: ByteVector,
                cipherText: ByteVector)

          ..${testVectorDeclarations}

          $allTestVectors
        }
        """

        val targetFile = targetDir / "bobcats" / "AESCBCTestVectors.scala"

        val formattedSyntax = Scalafmt
          .create(getClass.getClassLoader)
          .format(scalafmtConfig.toPath, targetFile.toPath, result.syntax)

        IO.write(targetFile, formattedSyntax)

        targetFile
      }

    resultFile.fold(
      err => throw new IllegalStateException(cats.Show[Parser.Error].show(err)),
      file => Set(file)
    )
  }
}
