package org.example

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.openssl.PKCS8Generator
import org.bouncycastle.pqc.legacy.math.linearalgebra.IntegerFunctions
import org.bouncycastle.util.io.pem.PemWriter
import java.io.File
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi


fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

@OptIn(ExperimentalEncodingApi::class)
fun bytesFromBase64String(str: String) = Base64.decode(str.replace("\n", ""))

fun RSAPrivateCrtKeyParameters.privateKeyInfo(): PrivateKeyInfo =
    PrivateKeyInfoFactory.createPrivateKeyInfo(this)

fun pkcs8(key: RSAPrivateCrtKeyParameters): String =
    StringWriter().use {
        PemWriter(it).use { pw ->
            pw.writeObject(
                PKCS8Generator(
                    key.privateKeyInfo(),
                    null
                )
            )
        }
        it.toString()
    }

fun derBytes(key: RSAPrivateCrtKeyParameters): ByteArray = key.privateKeyInfo().privateKey.octets

fun recoverPrimeFromCrtExponent(dq: BigInteger, publicExponent: BigInteger, start: Int = 3): Pair<Int, BigInteger>? {
    val d1_q = dq.multiply(publicExponent).minus(BigInteger.ONE)
    for (kInt in start..publicExponent.toInt()) {
        val k = kInt.toBigInteger()
        var h: BigInteger
        var r: BigInteger
        d1_q.divideAndRemainder(k).let { (quotient, remainder) ->
            h = quotient
            r = remainder
        }
        if (r != BigInteger.ZERO) continue

        val q = h.add(BigInteger.ONE)
        if (q.mod(BigInteger.TWO) == BigInteger.ZERO || !q.isProbablePrime(80)) continue
        return kInt to q
    }
    return null
}

private fun recoverFromLSB(dq: BigInteger, qInv: BigInteger, e: BigInteger, N: BigInteger, start: Int = 3): RSAPrivateCrtKeyParameters? {
    var currentIteration = start
    val eInt = e.toInt()
    while (currentIteration < eInt) {
        val recoveredPair = recoverPrimeFromCrtExponent(dq, e, start = currentIteration)
            ?: throw Exception("No key can be recovered")
        currentIteration = recoveredPair.first
        val recoveredQ = recoveredPair.second
        val recoveredP = N.divide(recoveredQ)
        val recoveredD = e.modInverse(IntegerFunctions.leastCommonMultiple(
            arrayOf(
                recoveredP.subtract(BigInteger.ONE),
                recoveredQ.subtract(BigInteger.ONE)
            )
        ))
        val recoveredDP = recoveredD.mod(recoveredP.subtract(BigInteger.ONE))

        try {
            val recoveredKey = RSAPrivateCrtKeyParameters(
                recoveredP.multiply(recoveredQ),
                e,
                recoveredD,
                recoveredP,
                recoveredQ,
                recoveredDP,
                dq,
                qInv
            )
            return recoveredKey
        } catch (e: IllegalArgumentException) {
            if (e.message == "RSA modulus is even") {
                currentIteration++
            } else {
                throw e
            }
        }
    }
    return null
}

@OptIn(ExperimentalEncodingApi::class)
fun main() {
    val dqBytes = bytesFromBase64String("""
        EudHSvDRivlR6OV4sad6WBJ8VCqIw9JvGL6UWvFlYYxRc5lZ6hqTe1v2AwnTQOsA
        PLshpu0ogQ3g21HSMG/B7O9WkZPpEe4iks1DJwKhNcFayCOg7qa8HFUKOCg+yhmx
        aa5y+8fhWqwoo3SxpJOTBdOTAQTNlqAabvaHAvMUGoEmInNVELpTA7W6i10zhdRE
        UA9JhZ2sI2i11j2WM4zTdXeDqOo1QOG1PfXUEinQ3JpZKQncsSoTyfcUY531lUv3
        kjxwQXdcxMD6a8bOGHT+emWtE5mL6Rz185CHf3MCbQ+u62fvbpN8nnjAKdtLBJKN
        27RrtxrTrOz5Z40DVwkUEw==
    """.trimIndent())

    val qInvBytes = bytesFromBase64String("""
        ALL/6NQwADUzduM6xzGpaUuiQVxrouAuNFsyMXkdqGGW3ddWx3EnI+S/Sp6Afvm0
        hfSk4l87Y1qnRurymWPMHW/oPxLChR35YgcpNVKFhpJq+M8UXp59rWwuDTm4N8mg
        4INOOzptJuEyUebS5NJTPG1xbtN9yJHodbj7M7z8nnUZ8hqOMCsXycPp80f0BnaJ
        PfnNFpL2Eep1A7IMg7KmQKiVupW+YrAezFICgGxGIjluta4dTHnC64d+IWl9JRlM
        lKMhDuRYMCie3tCtXFTeYcA3HoVSzJs3RMwZk9pBsW+8o+4pu7SrGShFVHCNp0YU
        wscbfHEjRv6u8gJfU3yZIUE=
    """.trimIndent())

    val pubkeyBytes = bytesFromBase64String("""
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2rmjsO9JKdoGfjkPnAwK
        Vzox8xqGSptpF2LqugfmLNy9CX7HBeP3IrRgoW+tGJC96Hj/wz+KOvLBDeXZ4lLy
        +1tkt1QO2PiE+IzYnmmGv+RHo2c2set5/8kkFlYc6je2kG1xc6ELACMcsZd9EEyu
        waHeKLloY+krzEJ9d5mDxbaltboqiCTFsQM9+LuTBFjKkzKjFCctVppVYWfrX/Vv
        eyITYbcsQnqFR+yLl4PeIpPjBr3kT9hryzeIcgIRnqhN9uajFPvjr7grJJWQkUcD
        4WSkSl9KIe+RAR/YR2EpWBs83gjoQZ8+BM6Dk5XEUT9AR87tmXvgoieFNYJX5E6A
        Lotz7hWZp10lTuhuVF/hziEtMdcCOkpaLcSeUksFPjWkteANAwqo8S7TSXJFJ/nw
        xQSaxmprLMfyLGrwSxXmt1ssMygFZVEU31mVa0bcje/SUJLf3mjyZOJwqdQoRWVr
        Pqa217ETQkzsXAJPrzPn/UJ6AGPiE0Hq8QJEKo3EVqExJnxCmPHvkkERIxYt8hLt
        T7bOVLX4UsgfRtqRUcDlSoBRE1cabbkLIMyihOb1vAHlEr7BXNv/MZa8CBwcjj3w
        V/8Och38l0pGEguXrMj0k8FE0oROAmIZiHzYThCA9PlkDMWEEFTeN88KEyAc85qS
        MsiWfQ5ak+5LbPfzAiGsOqUCAwEAAQ==
    """.trimIndent())
    val pubkey = KeyFactory.getInstance("RSA")
        .generatePublic(X509EncodedKeySpec(pubkeyBytes)) as RSAPublicKey

    val dQ = BigInteger(dqBytes)
    val qInv = BigInteger(qInvBytes)

    val recovered = recoverFromLSB(dQ, qInv, pubkey.publicExponent, pubkey.modulus)
        ?: throw Exception("Could not recover key from LSB")

    val recoveredPkcs8 = pkcs8(recovered)

    println("Recovered: $recoveredPkcs8")
    File("./recovered.der").writeBytes(derBytes(recovered))
}
