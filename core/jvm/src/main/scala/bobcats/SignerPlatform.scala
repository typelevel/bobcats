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

package bobcats

import cats.effect.kernel.Sync
import scodec.bits.ByteVector

import java.security
import java.security.{KeyFactory, Signature}

private[bobcats] trait SignerPlatform[F[_]]

private[bobcats] trait SignerCompanionPlatform {
	implicit def forSync[F[_]](implicit F: Sync[F]): Signer[F] =
		new UnsealedSigner[F] {
			//one would really want a type that pairs the PKA and Sig, so as not to leave impossible combinations open
			override def sign[A <: PrivateKeyAlg, S <: PKA.Signature](
			  spec: PrivateKeySpec[A],
			  sigType: S,
			  data: ByteVector
			): F[ByteVector] =
				F.catchNonFatal{
					val kf: KeyFactory = KeyFactory.getInstance(spec.algorithm.toStringJava)
					val privSpec: java.security.spec.KeySpec = spec.toJava
					val priv: security.PrivateKey = kf.generatePrivate(privSpec)
					// we don't use the provider here! Should we? How would we?
					// sig is not thread safe, so we can't reuse one
					// we had the following
					//val sig = Signature.getInstance(sigType.toStringJava)
					// but RSASSA-PSS needs this:
					val sig = {
						val rsapss = Signature.getInstance("RSASSA-PSS")
						import java.security.spec.{PSSParameterSpec, MGF1ParameterSpec}
						val pssSpec = new PSSParameterSpec(
							"SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)
						println("PSSParameterSpec="+pssSpec)
						rsapss.setParameter(pssSpec)
						rsapss
					}
					sig.initSign(priv)
					sig.update(data.toByteBuffer)
					ByteVector.view(sig.sign())
				}
		}
}

