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

import cats.effect.kernel.{Async, Resource}

private[bobcats] trait CryptoCompanionPlatform {
  def forAsync[F[_]](implicit F: Async[F]): Resource[F, Crypto[F]] = {
    Resource.pure(
      if (facade.isNodeJSRuntime) {
        new UnsealedCrypto[F] {
          override def hash: Hash[F] = Hash.forSyncNodeJS
          override def hmac: Hmac[F] = Hmac.forAsyncNodeJS
        }
      } else {
        new UnsealedCrypto[F] {
          override def hash: Hash[F] = Hash.forAsyncSubtleCrypto
          override def hmac: Hmac[F] = Hmac.forAsyncSubtleCrypto
        }
      }
    )
  }
}
