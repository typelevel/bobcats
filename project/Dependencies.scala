package bobcats

import org.portablescala.sbtplatformdeps.PlatformDepsPlugin.autoImport._
import sbt.Keys._
import sbt._

import scala.language.implicitConversions

object Dependencies {

  object Versions {
    val cats = "2.8.0"
    val catsEffect = "3.3.14"
    val scodecBits = "1.1.34"
    val munit = "0.7.29"
    val munitCE = "1.0.7"
    val disciplineMUnit = "1.0.9"
    val bouncy = "1.72"
    val dom = "2.3.0"
    val nimbus = "9.25.6"
  }
  import Dependencies.{Versions => V}

  object jdk {

    /**
     * BouncyCastle (for parsing PEM encoded objects in test) MIT style License
     *
     * @see
     *   https://www.bouncycastle.org/latest_releases.html
     * @see
     *   https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15to18/
     */
    object bouncy {
      val pkix = "org.bouncycastle" % "bcpkix-jdk15to18" % V.bouncy % Test
      val prov = "org.bouncycastle" % "bcprov-jdk15to18" % V.bouncy % Test
      val tls = "org.bouncycastle" % "bctls-jdk15to18" % V.bouncy % Test
    }

    /**
     * Needed for Java JWK support (JS Web Crypto API supports it natively)
     * @see
     *   https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-conversion
     * @see
     *   https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
     * @see
     *   https://hackmd.io/@FCN75Uk9TCqMmxSE6vEn5A/rkhCBUP0O for an overview of many jwk crypto
     *   libs
     */
    object nimbus {
      val jose_jwt = "com.nimbusds" % "nimbus-jose-jwt" % V.nimbus
    }
  }

  object scala {
    val cats = Def.setting("org.typelevel" %%% "cats-core" % V.cats)
    val catsEffect = Def.setting("org.typelevel" %%% "cats-effect-kernel" % V.catsEffect)
    val scodec = Def.setting("org.scodec" %%% "scodec-bits" % V.scodecBits)
  }

  object scalajs {
    val dom = Def.setting("org.scala-js" %%% "scalajs-dom" % V.dom)
  }

  object tests {
    val munit = Def.setting("org.scalameta" %%% "munit" % V.munit % Test)
    val catsLaws = Def.setting("org.typelevel" %%% "cats-laws" % V.cats % Test)
    val discipline =
      Def.setting("org.typelevel" %%% "discipline-munit" % V.disciplineMUnit % Test)
    val munit_cats = Def.setting("org.typelevel" %%% "munit-cats-effect-3" % V.munitCE % Test)
  }
}
