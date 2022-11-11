/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import JSEnv._
import bobcats.{Dependencies => D}
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxOptions
import org.scalajs.jsenv.selenium.SeleniumJSEnv

name := "bobcats"

ThisBuild / tlBaseVersion := "0.3"
ThisBuild / tlUntaggedAreSnapshots := true

// ThisBuild / organization := "org.typelevel"
ThisBuild / organization := "net.bblfish.crypto" // TODO remove
ThisBuild / developers := List(
  tlGitHubDev("armanbilge", "Arman Bilge"),
  tlGitHubDev("bblfish", "Henry Story")
)
ThisBuild / startYear := Some(2021)

enablePlugins(TypelevelCiReleasePlugin)
enablePlugins(TypelevelSonatypePlugin)

ThisBuild / crossScalaVersions := Seq("3.2.1", "2.13.10")

ThisBuild / githubWorkflowBuildPreamble ++= Seq(
  WorkflowStep.Use(
    UseRef.Public("actions", "setup-node", "v3"),
    name = Some("Setup NodeJS v16 LTS"),
    params = Map("node-version" -> "16"),
    cond = Some("matrix.project == 'rootJS' && matrix.jsenv == 'NodeJS'")
  )
)

ThisBuild / tlJdkRelease := Some(9)
// links to java  https://github.com/actions/setup-java
// list of jdks for scala  https://github.com/typelevel/jdk-index
// note jdk 11 is out because of ED25519 support (send in patch using libs like google tink if earlier versions needed)
ThisBuild / githubWorkflowJavaVersions := Seq(JavaSpec.temurin("19"), JavaSpec.temurin("17"))

val jsenvs = List(NodeJS, Chrome, Firefox).map(_.toString)
ThisBuild / githubWorkflowBuildMatrixAdditions += "jsenv" -> jsenvs
ThisBuild / githubWorkflowBuildSbtStepPreamble += s"set Global / useJSEnv := JSEnv.$${{ matrix.jsenv }}"
ThisBuild / githubWorkflowBuildMatrixExclusions ++= {
  for {
    scala <- (ThisBuild / crossScalaVersions).value.init
    jsenv <- jsenvs.tail
  } yield MatrixExclude(Map("scala" -> scala, "jsenv" -> jsenv))
}
ThisBuild / githubWorkflowBuildMatrixExclusions ++= {
  for {
    jsenv <- jsenvs.tail
  } yield MatrixExclude(Map("project" -> "rootJVM", "jsenv" -> jsenv))
}

lazy val useJSEnv =
  settingKey[JSEnv]("Use Node.js or a headless browser for running Scala.js tests")

Global / useJSEnv := NodeJS

ThisBuild / Test / jsEnv := {
  val old = (Test / jsEnv).value

  useJSEnv.value match {
    case NodeJS => old
    case Firefox =>
      val options = new FirefoxOptions()
      options.setHeadless(true)
      new SeleniumJSEnv(options)
    case Chrome =>
      val options = new ChromeOptions()
      options.setHeadless(true)
      new SeleniumJSEnv(options)
  }
}

lazy val root = tlCrossRootProject.aggregate(core, testRuntime)

lazy val core = crossProject(JSPlatform, JVMPlatform)
  .in(file("core"))
  .settings(
    name := "bobcats",
    // sonatypeCredentialHost := "s01.oss.sonatype.org", // TODO remove
    libraryDependencies ++= Seq(
      D.scala.cats.value,
      D.scala.catsEffect.value,
      D.scala.scodec.value,
      D.tests.munit.value,
      D.tests.catsLaws.value,
      D.scala.catsEffect.value,
      D.tests.discipline.value,
      D.tests.munit_cats.value
    ),
    Test / packageBin / publishArtifact := true,
    Test / packageDoc / publishArtifact := false,
    Test / packageSrc / publishArtifact := true
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      D.jdk.bouncy.pkix,
      D.jdk.bouncy.prov,
      D.jdk.bouncy.tls,
      D.jdk.nimbus.jose_jwt
    )
  )
  .jsSettings(libraryDependencies ++= Seq(
    D.scalajs.dom.value
  ))
  .dependsOn(testRuntime % Test)

lazy val testRuntime = crossProject(JSPlatform, JVMPlatform)
  .crossType(CrossType.Pure)
  .in(file("test-runtime"))
  .enablePlugins(BuildInfoPlugin, NoPublishPlugin)
  .settings(
    buildInfoPackage := "bobcats"
  )
  .jvmSettings(
    buildInfoKeys := Seq(
      BuildInfoKey.sbtbuildinfoConstantEntry("runtime" -> "JVM")
    )
  )
  .jsSettings(
    buildInfoKeys := Seq(
      BuildInfoKey("runtime" -> useJSEnv.value.toString)
    )
  )
