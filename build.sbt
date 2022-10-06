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

import org.openqa.selenium.WebDriver
import org.openqa.selenium.chrome.{ChromeDriver, ChromeOptions}
import org.openqa.selenium.firefox.{FirefoxOptions, FirefoxProfile}
import org.openqa.selenium.remote.server.{DriverFactory, DriverProvider}
import org.scalajs.jsenv.selenium.SeleniumJSEnv

import JSEnv._

name := "bobcats"

ThisBuild / tlBaseVersion := "0.2"
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

ThisBuild / tlCiReleaseBranches := Seq("main")
// ThisBuild / tlSonatypeUseLegacyHost := false // TODO remove

ThisBuild / crossScalaVersions := Seq("3.1.3", "2.12.15", "2.13.9")

ThisBuild / githubWorkflowBuildPreamble ++= Seq(
  WorkflowStep.Use(
    UseRef.Public("actions", "setup-node", "v2.4.0"),
    name = Some("Setup NodeJS v14 LTS"),
    params = Map("node-version" -> "14"),
    cond = Some("matrix.ci == 'ciJS'")
  )
)
ThisBuild / tlJdkRelease := Some(9)

ThisBuild / githubWorkflowJavaVersions := Seq(JavaSpec.temurin("17"), JavaSpec.temurin("11"))

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

val catsVersion = "2.8.0"
val catsEffectVersion = "3.3.14"
val scodecBitsVersion = "1.1.33"
val munitVersion = "1.0.0-M6"
val munitCEVersion = "1.0.7"
val disciplineMUnitVersion = "1.0.9"
val bouncyVersion = "1.72"
val domVersion = "2.3.0"
val nimbusJWTVersion = "9.25.4"

lazy val root =
  project.in(file(".")).aggregate(rootJS, rootJVM).enablePlugins(NoPublishPlugin)
lazy val rootJVM =
  project.aggregate(core.jvm, testRuntime.jvm).enablePlugins(NoPublishPlugin)
lazy val rootJS =
  project.aggregate(core.js, testRuntime.js).enablePlugins(NoPublishPlugin)

lazy val core = crossProject(JSPlatform, JVMPlatform)
  .in(file("core"))
  .settings(
    name := "bobcats",
    // sonatypeCredentialHost := "s01.oss.sonatype.org", // TODO remove
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "org.scalameta" %%% "munit" % munitVersion % Test,
      "org.typelevel" %%% "cats-laws" % catsVersion % Test,
      "org.typelevel" %%% "cats-effect" % catsEffectVersion % Test,
      "org.typelevel" %%% "discipline-munit" % disciplineMUnitVersion % Test,
      "org.typelevel" %%% "munit-cats-effect-3" % munitCEVersion % Test
    ),
    Test / packageBin / publishArtifact := true,
    Test / packageDoc / publishArtifact := false,
    Test / packageSrc / publishArtifact := true
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcpkix-jdk15to18" % bouncyVersion % Test,
      "org.bouncycastle" % "bcprov-jdk15to18" % bouncyVersion % Test,
      "org.bouncycastle" % "bctls-jdk15to18" % bouncyVersion % Test,
      "com.nimbusds" % "nimbus-jose-jwt" % nimbusJWTVersion % Test
    )
  )
  .jsSettings(
    libraryDependencies += "org.scala-js" %%% "scalajs-dom" % domVersion
  )
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
