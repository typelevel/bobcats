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

import java.security.{NoSuchAlgorithmException, Provider, Security}

private[bobcats] final class Providers(val ps: Array[Provider]) extends AnyVal {

  private def provider(service: String, name: String): Option[Provider] =
    ps.find(provider => provider.getService(service, name) != null)

  def messageDigest(name: String): Either[NoSuchAlgorithmException, Provider] =
    provider("MessageDigest", name).toRight(
      new NoSuchAlgorithmException(s"${name} MessageDigest not available"))

  def mac(name: String): Either[NoSuchAlgorithmException, Provider] =
    provider("Mac", name).toRight(new NoSuchAlgorithmException(s"${name} Mac not available"))

}

private[bobcats] object Providers {
  def get(): Providers = new Providers(Security.getProviders().clone())
}
