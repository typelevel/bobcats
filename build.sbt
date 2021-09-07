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

ThisBuild / baseVersion := "0.1"

// ThisBuild / organization := "org.typelevel"
ThisBuild / organization := "com.armanbilge" // TODO remove
ThisBuild / organizationName := "Typelevel"
ThisBuild / publishGithubUser := "armanbilge"
ThisBuild / publishFullName := "Arman Bilge"

enablePlugins(SonatypeCiReleasePlugin)
ThisBuild / spiewakCiReleaseSnapshots := true
ThisBuild / spiewakMainBranches := Seq("main")

ThisBuild / homepage := Some(url("https://github.com/typelevel/bobcats"))
ThisBuild / scmInfo := Some(
  ScmInfo(url("https://github.com/typelevel/bobcats"), "git@github.com:typelevel/bobcats.git"))
sonatypeCredentialHost := "s01.oss.sonatype.org" // TODO remove

ThisBuild / crossScalaVersions := Seq("3.0.2", "2.12.14", "2.13.6")

ThisBuild / githubWorkflowBuildPreamble ++= Seq(
  WorkflowStep.Use(
    UseRef.Public("actions", "setup-node", "v2.1.2"),
    name = Some("Setup NodeJS v14 LTS"),
    params = Map("node-version" -> "14")
  )
)

replaceCommandAlias("ci", CI.AllCIs.map(_.toString).mkString)
addCommandAlias("ciJVM", CI.JVM.toString)
addCommandAlias("ciNodeJS", CI.NodeJS.toString)
addCommandAlias("ciFirefox", CI.Firefox.toString)
addCommandAlias("ciChrome", CI.Chrome.toString)

addCommandAlias("prePR", "; root/clean; scalafmtSbt; +root/scalafmtAll; +root/headerCreate")

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

val catsVersion = "2.6.1"
val catsEffectVersion = "3.2.8"
val scodecBitsVersion = "1.1.28"
val munitVersion = "0.7.29"
val munitCEVersion = "1.0.5"

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
    sonatypeCredentialHost := "s01.oss.sonatype.org", // TODO remove
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "org.scalameta" %%% "munit" % "0.7.29" % Test,
      "org.typelevel" %%% "cats-effect" % catsEffectVersion % Test,
      "org.typelevel" %%% "munit-cats-effect-3" % munitCEVersion % Test
    )
  )
  .jsSettings(
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-effect" % catsEffectVersion
    )
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
