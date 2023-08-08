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

import java.security.{NoSuchAlgorithmException, Security}
import fs2.{Pipe, Stream}
import cats.effect.kernel.{Async, Sync}
import scodec.bits.ByteVector

private[bobcats] trait HashCompanionPlatform {

  private[bobcats] def forSync[F[_]](implicit F: Sync[F]): Hash[F] = {
    // TODO: What to do with this?
    val providers = Security.getProviders().clone()
    new UnsealedHash[F] {
      override def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] = {
        val name = algorithm.toStringJava
        Hash1.providerForName(providers, name) match {
          case None =>
            F.raiseError(new NoSuchAlgorithmException(s"${name} MessageDigest not available"))
          case Some(p) => new JavaSecurityDigest(name, p).digest(data)
        }
      }

      override def digestPipe(algorithm: HashAlgorithm): Pipe[F, Byte, Byte] = {
        val name = algorithm.toStringJava
        Hash1.providerForName(providers, name) match {
          case None =>
            _ =>
              Stream.eval(
                F.raiseError(
                  new NoSuchAlgorithmException(s"${name} MessageDigest not available")))
          case Some(p) => new JavaSecurityDigest(name, p).pipe
        }
      }
    }
  }

  def forAsync[F[_]](implicit F: Async[F]): Hash[F] = forSync(F)
}
