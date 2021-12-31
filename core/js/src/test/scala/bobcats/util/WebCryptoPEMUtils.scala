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

import bobcats.{AsymmetricKeyAlg, PrivateKeySpec, PublicKeySpec, util}
import scodec.bits.ByteVector

import scala.util.matching.Regex
import scala.util.{Failure, Success, Try}

/** the JS Crypto API does not give us the tools to parse a PEM in a way that
 * we end up with a pure key. So we will just assume the PEM given is correct and
 * build the specs from that.
 *
 * note: this class uses no JS libs, so it could be the default
 *
 * the whole problem here is that we are forced to pass the encoding of the key, where
 * that information is located IN the PKCS8 key. JS WebCrypto API cannot parse PKCS1 keys
 * where the that information is located in the ----- headers ----- (which we could parse)
 * because the JS Crypto API does not understand that format.
 *
 * So as a result this library is not very helpful for use on the Web, where one may
 * come across keys in PKCS1 format or keys in PKCS8 format and not know the key type
 *
 * To make it useful on the web we would need to find a JS library that can parse a PKCS1 and
 * PKCS8 file without needing to know the key type.
 */

object WebCryptoPEMUtils extends util.PEMUtils {

	override def getPrivateKeyFromPEM(
	  pemStr: PKCS8_PEM,
	  keyType: AsymmetricKeyAlg
	): Try[PrivateKeySpec[AsymmetricKeyAlg]]= {
		println("in getPrivateKeyFromPEM")
		for {
			base64data <- pemData(pemStr)
			bytes: ByteVector <- ByteVector.fromBase64(base64data).toRight(
				new Exception("not base64 data")
			).toTry
		} yield {
			PrivateKeySpec(bytes, keyType)
		}
	}

	val PEMContent: Regex = "(?s)-----BEGIN[A-Z ]+KEY-----(.*)-----END[A-Z ]+KEY-----".r

	def pemData(pem: String): Try[String] =
		pem match {
			case PEMContent(s) => Success(s.filterNot(_.isWhitespace))
			case e => Failure(new Exception("does not match PEM syntax. " + e))
		}

	override def getPublicKeyFromPEM(
	  pemStr: SPKI_PEM,
	  keyType: AsymmetricKeyAlg
	): Try[PublicKeySpec[AsymmetricKeyAlg]] = {
		println("in getPrivateKeyFromPEM")
		for {
			base64data <- pemData(pemStr)
			bytes: ByteVector <- (ByteVector.fromBase64(base64data).toRight(
				new Exception("not base64 data")
			)).toTry
		} yield {
			PublicKeySpec(bytes, keyType)
		}
	}


}
