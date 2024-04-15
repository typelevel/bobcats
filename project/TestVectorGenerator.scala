import cats.syntax.all._
import sbt._
import sbt.nio.file.FileTreeView
import scala.meta._
import scodec.bits._
import scodec.bits.Bases.Alphabets
import cats.parse.Parser
import org.scalafmt.sbt.ScalafmtPlugin

trait TestVectorGenerator {

  def generate(testFiles: Seq[File]): Source

  def task(key: TaskKey[Seq[File]], file: String) = {
    import Keys._
    Def.task {
      val files = key.inputFiles
      val targetDir = (Test / sourceManaged).value
      val scalafmtCfg = ScalafmtPlugin.autoImport.scalafmtConfig.value

      val result = generate(files.map(_.toFile))
      val targetFile = targetDir / "bobcats" / s"${file}.scala"

      val formattedSyntax = ScalafmtPlugin
        .globalInstance
        .format(scalafmtCfg.toPath, targetFile.toPath, result.syntax)

      IO.write(targetFile, formattedSyntax)

      Seq(targetFile)
    }
  }
}

object TestVectorGenerator {
  def hexInterpolate(data: ByteVector): Term =
    if (data.isEmpty) {
      q"ByteVector.empty"
    } else {
      Term.Interpolate(
        Term.Name("hex"),
        List(Lit.String(data.toHex(Alphabets.HexLowercase))),
        List.empty)
    }
}
