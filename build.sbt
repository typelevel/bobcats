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

ThisBuild / tlBaseVersion := "0.1"
ThisBuild / tlUntaggedAreSnapshots := false

ThisBuild / developers := List(
  tlGitHubDev("armanbilge", "Arman Bilge")
)
ThisBuild / startYear := Some(2021)

ThisBuild / crossScalaVersions := Seq("3.3.3", "2.12.17", "2.13.8")

ThisBuild / githubWorkflowBuildPreamble ++= Seq(
  WorkflowStep.Use(
    UseRef.Public("actions", "setup-node", "v3"),
    name = Some("Setup NodeJS v16 LTS"),
    params = Map("node-version" -> "16"),
    cond = Some("matrix.project == 'rootJS' && matrix.jsenv == 'NodeJS'")
  )
)

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

val catsVersion = "2.8.0"
val fs2Version = "3.7.0"
val catsEffectVersion = "3.5.4"
val scodecBitsVersion = "1.1.35"
val munitVersion = "1.0.0-M8"
val munitCEVersion = "2.0.0-M3"
val disciplineMUnitVersion = "2.0.0-M2"

lazy val root = tlCrossRootProject.aggregate(core, testRuntime)

lazy val core = crossProject(JSPlatform, JVMPlatform, NativePlatform)
  .in(file("core"))
  .settings(
    name := "bobcats",
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "co.fs2" %%% "fs2-core" % fs2Version,
      "org.scalameta" %%% "munit" % munitVersion % Test,
      "org.typelevel" %%% "cats-laws" % catsVersion % Test,
      "org.typelevel" %%% "cats-effect" % catsEffectVersion % Test,
      "org.typelevel" %%% "discipline-munit" % disciplineMUnitVersion % Test,
      "org.typelevel" %%% "munit-cats-effect" % munitCEVersion % Test
    )
  )
  .dependsOn(testRuntime % Test)

lazy val testRuntime = crossProject(JSPlatform, JVMPlatform, NativePlatform)
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
  .nativeSettings(
    buildInfoKeys := Seq(
      BuildInfoKey.sbtbuildinfoConstantEntry("runtime" -> "Native")
    )
  )
