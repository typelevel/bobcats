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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.util.io.pem.PemObject
import scodec.bits.ByteVector

import java.io.{StringReader, StringWriter}
import java.security
import java.security.{PrivateKey, PublicKey}
import scala.util.Try

/**
 * BouncyCastle supports PKCS1 formatted PEM files.
 * But there is an answer that does not require Bouncy given here to try out later
 * https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
 * */
object BouncyJavaPEMUtils extends util.PEMUtils {
	java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)

	override def getPrivateKeyFromPEM(pemStr: String, keyType: AsymmetricKeyAlg): Try[PrivateKeySpec[AsymmetricKeyAlg]] =
		for {
			privateKey <- PEMtoPrivateKey(pemStr)
//			alg <- AsymmetricKeyAlg.fromStringJava(privateKey.getAlgorithm).toRight(
//				new Exception(s"could not find bobcats.Algorithm object for ${privateKey.getAlgorithm}")
//			).toTry
		} yield {
//			println("private key====>\n"+toPKCS8(privateKey))
			PrivateKeySpec(ByteVector.view(privateKey.getEncoded), keyType)
		}

	override def getPublicKeyFromPEM(pemStr: String, keyType: AsymmetricKeyAlg): Try[PublicKeySpec[AsymmetricKeyAlg]] =
		for {
			publicKey <- PEMToPublicKey(pemStr)
//			(alg: AsymmetricKeyAlg) <- AsymmetricKeyAlg.fromStringJava(publicKey.getAlgorithm).toRight(
//				new Exception(s"could not find bobcats.Algorithm object for ${publicKey.getAlgorithm}")
//			).toTry
//			if alg == keyType
		} yield {
//			println("public key====>\n"+toSPKI(publicKey))
			PublicKeySpec(ByteVector.view(publicKey.getEncoded), keyType)
		}

	def PEMtoPrivateKey(privateKeyPem: String): Try[security.PrivateKey] =
		Try {
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

	def PEMToPublicKey(publicKeyPem: String): Try[security.PublicKey] =
		Try {
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


	/** return PKCS8 format */
	def toPKCS8(privateKey: PrivateKey): String = {
		val sw = new StringWriter()
		val pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)
//					val pw = new org.bouncycastle.util.io.pem.PemWriter(sw)
		val pem = new PemObject("PRIVATE KEY", privateKey.getEncoded())

		pw.writeObject(pem)
		pw.flush()
		sw.toString
	}

	/** return PKCS8 format */
	def toSPKI(publicKey: PublicKey): String = {
		val sw = new StringWriter()
		val pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)
		//					val pw = new org.bouncycastle.util.io.pem.PemWriter(sw)
		val pem = new PemObject("PUBLIC KEY", publicKey.getEncoded())

		pw.writeObject(pem)
		pw.flush()
		sw.toString
	}
}
