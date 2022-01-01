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

import bobcats.util.StringUtils.StringW

/**
 * StringUtils has an implementation of part of RFC8792 string manipulation
 * https://datatracker.ietf.org/doc/html/rfc8792#section-7.2.2
 */
class Rfc8792Test extends munit.FunSuite {
  import scala.collection.immutable.{List => Line}

  // tricky example from https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-07.html#name-creating-a-signature
  // discussed https://github.com/httpwg/http-extensions/issues/1876
  test("example from Signing HTTP MEssages") {
    val example = """"@method": GET
							 |"@path": /foo
							 |"@authority": example.org
							 |"cache-control": max-age=60, must-revalidate
							 |"x-empty-header": \
							 |
							 |"x-example": Example header with some whitespace.
							 |"@signature-params": ("@method" "@path" "@authority" \
							 |  "cache-control" "x-empty-header" "x-example");created=1618884475\
							 |  ;keyid="test-key-rsa-pss"""".rfc8792single

    // A Seq of Lines.
    val expected = Seq(
      Line(""""@method": GET"""),
      Line(""""@path": /foo"""),
      Line(""""@authority": example.org"""),
      Line(""""cache-control": max-age=60, must-revalidate"""),
      Line(""""x-empty-header": """, """"""),
      Line(""""x-example": Example header with some whitespace."""),
      Line(
        """"@signature-params": ("@method" "@path" "@authority" """,
        """"cache-control" "x-empty-header" "x-example");created=1618884475""",
        """;keyid="test-key-rsa-pss""""
      )
    ).map(_.mkString("")).mkString("\n")

    assertEquals(example, expected)
  }

}
