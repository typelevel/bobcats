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

import bobcats.{PKA, PrivateKeyAlg, PrivateKeySpec, PublicKeySpec, util}
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import scodec.bits.ByteVector

import java.io.StringReader
import java.security
import scala.util.Try


object BouncyJavaPEMUtils extends util.PEMUtils {
	java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)

	override def getPrivateKeyFromPEM(pemStr: String): Try[PrivateKeySpec[_]] =
		for {
			privateKey <- PEMtoPrivateKey(pemStr)
			alg <- PrivateKeyAlg.fromStringJava(privateKey.getAlgorithm).toRight(
				new Exception(s"could not find bobcats.Algorithm object for ${privateKey.getAlgorithm}")
			).toTry
		} yield
			PrivateKeySpec(ByteVector.view(privateKey.getEncoded), alg)

	override def getPublicKeyFromPEM(pemStr: String): Try[PublicKeySpec[_]] =
		for {
			publicKey <- PEMToPublicKey(pemStr)
			alg <- PKA.fromStringJava(publicKey.getAlgorithm).toRight(
				new Exception(s"could not find bobcats.Algorithm object for ${publicKey.getAlgorithm}")
			).toTry
		} yield
			PublicKeySpec(ByteVector.view(publicKey.getEncoded), alg)


	def PEMtoPrivateKey(privateKeyPem: String): Try[security.PrivateKey] = Try {
		val pem = new PEMParser(new java.io.StringReader(privateKeyPem))
		val jcaPEMKeyConverter = new JcaPEMKeyConverter
		val pemContent = pem.readObject
		if (pemContent.isInstanceOf[PEMKeyPair]) {
			val pemKeyPair = pemContent.asInstanceOf[PEMKeyPair]
			val keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair)
			keyPair.getPrivate
		}
		else if (pemContent.isInstanceOf[PrivateKeyInfo]) {
			val privateKeyInfo = pemContent.asInstanceOf[PrivateKeyInfo]
			jcaPEMKeyConverter.getPrivateKey(privateKeyInfo)
		}
		else throw new IllegalArgumentException("Unsupported private key format '" + pemContent.getClass.getSimpleName + '"')
	}

	def PEMToPublicKey(publicKeyPem: String): Try[security.PublicKey] = Try {
		val pem = new PEMParser(new StringReader(publicKeyPem))
		val jcaPEMKeyConverter = new JcaPEMKeyConverter
		val pemContent = pem.readObject
		if (pemContent.isInstanceOf[PEMKeyPair]) {
			val pemKeyPair = pemContent.asInstanceOf[PEMKeyPair]
			val keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair)
			keyPair.getPublic
		}
		else if (pemContent.isInstanceOf[SubjectPublicKeyInfo]) {
			val keyInfo = pemContent.asInstanceOf[SubjectPublicKeyInfo]
			jcaPEMKeyConverter.getPublicKey(keyInfo)
		}
		else if (pemContent.isInstanceOf[X509CertificateHolder]) {
			val cert = pemContent.asInstanceOf[X509CertificateHolder]
			jcaPEMKeyConverter.getPublicKey(cert.getSubjectPublicKeyInfo)
		}
		else throw new IllegalArgumentException("Unsupported public key format '" + pemContent.getClass.getSimpleName + '"')
	}
}