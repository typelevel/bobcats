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

package bobcats.util

import bobcats.{PrivateKeySpec, PublicKeySpec, util}
import cats.effect.Async
import org.scalajs.dom
import org.scalajs.dom.crypto
import scodec.bits.ByteVector
import cats.syntax.all._

import scala.scalajs.js
import scala.util.matching.Regex
import scala.util.{Failure, Success, Try}

object WebCryptoPEMUtils {

	implicit def forASyncIO[F[_]](implicit F0: Async[F]): PEMUtils[F] =
		new util.PEMUtils[F] {
			override def getPrivateKeyFromPEM(pemStr: String): F[PrivateKeySpec[_]] = {
				for {
					base64data <- F0.fromTry(pemData(pemStr))
					bytes: ByteVector <- F0.fromEither(ByteVector.fromBase64(base64data).toRight(
						new Exception("not base64 data")
					))
					x <- F0.fromPromise(
						F0.delay( crypto.subtle.importKey(
							org.scalajs.dom.KeyFormat.pkcs8,
							bytes.toUint8Array,
							null, //let's see if not specifying the key algorithm will help
							true,
							js.Array(dom.KeyUsage.sign)
						))
					)
				} yield {
					println("algorithm = "+x.algorithm)
					PrivateKeySpec(bytes, bobcats.PrivateKeyAlg.RSA)
				}

			}

			val PEMContent: Regex = "(?s)-----BEGIN[A-Z ]+KEY-----(.*)-----END[A-Z ]+KEY-----".r

			def pemData(pem: String): Try[String] =
				pem match {
					case PEMContent(s) => Success(s.filterNot(_.isWhitespace))
					case e => Failure(new Exception("does not match PEM syntax. " + e))
				}


			override def getPublicKeyFromPEM(pemStr: String): F[PublicKeySpec[_]] = ???
		}
}
