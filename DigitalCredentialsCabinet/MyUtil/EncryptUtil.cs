using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using java.security;
using javax.crypto;
using javax.crypto.spec;

namespace DigitalCredentialsCabinet.MyUtil
{
    class EncryptUtil
    { 
        private static Random random = new Random();
        private static Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        private static Provider BC_PROVIDER = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        private static Mac mac = Mac.getInstance("ISO9797Alg3Mac", BC_PROVIDER);

        private EncryptUtil() { }
        
        /// <summary>
        /// 外部直接调用的方法，可生成最终命令
        /// </summary>
        /// <param name="number"></param>
        /// <param name="dateOfBirth"></param>
        /// <param name="dateOfExpiry"></param>
        /// <param name="rndICC"></param>
        /// <returns></returns>
        public static byte[] doBAC(string number, string dateOfBirth, string dateOfExpiry, byte[] rndICC)
        {
            if ((dateOfBirth.Length != 6) || (dateOfExpiry.Length != 6) || (number.Length != 9) || (rndICC.Length != 8))
            {
                throw new Exception("生成keySeed参数有误!numberLength(9):"+ number.Length + "birthday(6):"+ dateOfBirth.Length + "dateOfExpory(6):"+ dateOfExpiry.Length);
            }

            byte[] keySeed = computekeyseed(number, dateOfBirth, dateOfExpiry, true);
            SecretKey kEnc = deriveKey(keySeed, 1);
            SecretKey kMac = deriveKey(keySeed, 2);//生成密钥
            byte[] capdu = GetApduCmd(kEnc, kMac, rndICC);
            
            /// 生成完整命令(报头+命令+数据) - Start
            byte[] cmdFinal = new byte[56];
            cmdFinal[0] = 0;
            cmdFinal[1] = 0;
            cmdFinal[2] = 255;//Convert.ToByte("FF", 16);
            cmdFinal[3] = 49;
            cmdFinal[4] = 207;//Convert.ToByte("CF", 16);
            cmdFinal[5] = 212;//Convert.ToByte("D4", 16);
            cmdFinal[6] = 64;// Convert.ToByte("40", 16);
            cmdFinal[7] = 1;
            Array.Copy(capdu, 0, cmdFinal, 8, 46);
            cmdFinal[55] = 0;
            /// 生成完整命令(报头+命令+数据) - End
            int sum = 0;
            for (int i = 5; i < 54; i++)
            {
                sum += cmdFinal[i];
            }
            string hexSum = Convert.ToString(sum, 16);
            hexSum = hexSum.Substring(hexSum.Length - 2, 2);
            int jy = 256 - Convert.ToByte(hexSum, 16);
            cmdFinal[54] = Convert.ToByte(jy);//倒数第二位-校验码

            return cmdFinal;
        }
        
        /// <summary>
        /// 生成包含CApdu的命令
        /// </summary>
        /// <param name="kEnc"></param>
        /// <param name="kMac"></param>
        /// <param name="rndICC">从芯片获取的随机数</param>
        /// <returns></returns>
        public static byte[] GetApduCmd(SecretKey kEnc, SecretKey kMac, byte[] rndICC)
        {
            byte[] rndIFD = new byte[8];
            random.NextBytes(rndIFD);
            byte[] kIFD = new byte[16];
            random.NextBytes(rndIFD);
            /// 加密过程 - Start
            IvParameterSpec ZERO_IV_PARAM_SPEC = new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            cipher.init(1, kEnc, ZERO_IV_PARAM_SPEC);//ENCRYPT_MODE = 1;
            /*
			 * cipher.update(rndIFD); cipher.update(rndICC); cipher.update(kIFD); 
			 * This doesn't work, apparently we need to create plaintext array. 
			 * Probably has something to do with ZERO_IV_PARAM_SPEC.
			 */
            byte[] plaintext = new byte[32];
            Array.Copy(rndIFD, 0, plaintext, 0, 8);
            Array.Copy(rndICC, 0, plaintext, 8, 8);
            Array.Copy(kIFD, 0, plaintext, 16, 16);
            byte[] ciphertext = cipher.doFinal(plaintext);
            if (ciphertext.Length != 32)
            {
                throw new Exception("Cryptogram wrong length " + ciphertext.Length);
            }

            mac.init(kMac);
            //Util.padWithMRZ(ciphertext)移出来，为一下5行代码
            byte[] byteMRZ = new byte[40];//start
            byte[] byte8 = new byte[8] {  0 ,0,0,0,0,0,0,0 };
            byte8[0] = Convert.ToByte("80", 16);
            Array.Copy(ciphertext, 0, byteMRZ, 0 ,32);
            Array.Copy(byte8, 0, byteMRZ, 32, 8);//end
            byte[] mactext = mac.doFinal(byteMRZ);
            if (mactext.Length != 8)
            {
                throw new Exception("MAC wrong length");
            }
            
            byte[] data = new byte[32 + 8];
            Array.Copy(ciphertext, 0, data, 0, 32);
            Array.Copy(mactext, 0, data, 32, 8);
            /// 加密过程 - End , data即是加密后的数据

            /// 生成CApdu - Start
            byte[] capdu = new byte[46];
            capdu[0] = 0;
            capdu[1] = Convert.ToByte("82", 16);
            capdu[2] = 0;
            capdu[3] = 0;
            capdu[4] = Convert.ToByte("28", 16);
            Array.Copy(data, 0, capdu, 5,40);
            capdu[45] = 40;
            /// 生成CApdu - End
            return capdu;
        }

        
        /// <summary>
        /// Derives a shared key.
        /// </summary>
        /// <param name="keySeed"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        private static SecretKey deriveKey(byte[] keySeed, int mode)
        {
            int keyLength = 128;
            string cipherAlg = "DESede";
            string digestAlg = inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg, keyLength);
            MessageDigest digest = MessageDigest.getInstance(digestAlg);
            digest.reset();
            digest.update(keySeed);
            //if (nonce != null)//nonce为null
            //{
            //    digest.update(nonce);
            //}
            digest.update(new byte[] { 0x00, 0x00, 0x00, (byte)mode });
            byte[] hashResult = digest.digest();
            byte[] keyBytes = null;
            if (string.Equals("DESede", cipherAlg, StringComparison.CurrentCultureIgnoreCase) || string.Equals("3DES", cipherAlg, StringComparison.CurrentCultureIgnoreCase))
            {
                switch (keyLength)
                {
                    case 112:
                    case 128:
                        keyBytes = new byte[24];
                        Array.Copy(hashResult, 0, keyBytes, 0, 8);
                        Array.Copy(hashResult, 8, keyBytes, 8, 8);
                        Array.Copy(hashResult, 0, keyBytes, 16, 8);
                        break;
                    default:
                        throw new Exception("KDF can only use DESede with 128-bit key length");
                }
            }
            else if(string.Equals("AES", cipherAlg, StringComparison.CurrentCultureIgnoreCase)
                || cipherAlg.StartsWith("AES"))
            {
                switch (keyLength)
                {
                    case 128:
                        keyBytes = new byte[16];
                        Array.Copy(hashResult, 0, keyBytes,0, 16);
                        break;
                    case 192:
                        keyBytes = new byte[24];
                        Array.Copy(hashResult, 0, keyBytes, 0, 24);
                        break;
                    case 256:
                        keyBytes = new byte[32];
                        Array.Copy(hashResult, 0, keyBytes, 0, 32);
                        break;
                    default:
                        throw new Exception("KDF can only use AES with 128-bit, 192-bit key or 256-bit length, found: " + keyLength + "-bit key length");
                }
            }
            return new SecretKeySpec(keyBytes, cipherAlg);
        }

        private static string inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(string cipherAlg, int keyLength)
        {
            if (cipherAlg == null) { throw new Exception("Class:EncryptUtil-Function:inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation()的cipherAlg为空!"); }
            if ("DESede".Equals(cipherAlg) || "AES-128".Equals(cipherAlg)) { return "SHA-1"; }
            if ("AES".Equals(cipherAlg) && keyLength == 128) { return "SHA-1"; }
            if ("AES-256".Equals(cipherAlg) || "AES-192".Equals(cipherAlg)) { return "SHA-256"; }
            if ("AES".Equals(cipherAlg) && (keyLength == 192 || keyLength == 256)) { return "SHA-256"; }
            throw new Exception("Unsupported cipher algorithm or key length \"" + cipherAlg + "\", " + keyLength);
        }
        
        /// <summary>
        /// 生成keySeed
        /// </summary>
        /// <param name="documentnumber"></param>
        /// <param name="dateofbirth"></param>
        /// <param name="dateofexpiry"></param>
        /// <param name="dotruncate">true</param>
        /// <returns></returns>
        /// 测试无误，返回正确keySeed
        private static byte[] computekeyseed(string documentnumber, string dateofbirth, string dateofexpiry, bool dotruncate)
        {
            //byte[] aaa = System.Text.Encoding.UTF8.GetBytes(documentnumber);
            byte[] documentnumbercheckdigit = { (byte)checkDigit(documentnumber, false) };
            byte[] dateofbirthcheckdigit = { (byte)checkDigit(dateofbirth, false) };
            byte[] dateofexpirycheckdigit = { (byte)checkDigit(dateofexpiry, false) };
            MessageDigest shaDigest = MessageDigest.getInstance("SHA-1");
            shaDigest.update(GetBytes(documentnumber));
            shaDigest.update(documentnumbercheckdigit);
            shaDigest.update(GetBytes(dateofbirth));
            shaDigest.update(dateofbirthcheckdigit);
            shaDigest.update(GetBytes(dateofexpiry));
            shaDigest.update(dateofexpirycheckdigit);
            byte[] hash = shaDigest.digest();
            if (dotruncate)
            {
                byte[] keySeed = new byte[16];
                Array.Copy(hash, keySeed, 16);
                return keySeed;
            }
            else
            {
                return hash;
            }
        }

        /// <summary>
        /// 返回字符串的byte[]
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static byte[] GetBytes(string str)
        {
            return System.Text.Encoding.UTF8.GetBytes(str);
        }

        private static char checkDigit(string str, bool preferFillerOverZero)
        {
            byte[] chars;
            if (str == null)
            {
                chars = new byte[] { };
            }
            else
            {
                chars = GetBytes(str);
            }
            int[] weights = { 7, 3, 1 };
            int result = 0;
            for (int i = 0; i < chars.Length; i++)
            {
                result = (result + weights[i % 3] * decodeMRZDigit((char)chars[i])) % 10;
            }
            string checkDigitString = result.ToString();
            if (checkDigitString.Length != 1) { throw new Exception("Error in computing check digit."); }
            char checkDigit = (char)GetBytes(checkDigitString)[0];
            if (preferFillerOverZero && checkDigit == '0') { checkDigit = '<'; }
            return checkDigit;
        }

        private static int decodeMRZDigit(char ch)
        {
            switch (ch)
            {
                case '<':
                case '0': return 0;
                case '1': return 1;
                case '2': return 2;
                case '3': return 3;
                case '4': return 4;
                case '5': return 5;
                case '6': return 6;
                case '7': return 7;
                case '8': return 8;
                case '9': return 9;
                case 'a': case 'A': return 10;
                case 'b': case 'B': return 11;
                case 'c': case 'C': return 12;
                case 'd': case 'D': return 13;
                case 'e': case 'E': return 14;
                case 'f': case 'F': return 15;
                case 'g': case 'G': return 16;
                case 'h': case 'H': return 17;
                case 'i': case 'I': return 18;
                case 'j': case 'J': return 19;
                case 'k': case 'K': return 20;
                case 'l': case 'L': return 21;
                case 'm': case 'M': return 22;
                case 'n': case 'N': return 23;
                case 'o': case 'O': return 24;
                case 'p': case 'P': return 25;
                case 'q': case 'Q': return 26;
                case 'r': case 'R': return 27;
                case 's': case 'S': return 28;
                case 't': case 'T': return 29;
                case 'u': case 'U': return 30;
                case 'v': case 'V': return 31;
                case 'w': case 'W': return 32;
                case 'x': case 'X': return 33;
                case 'y': case 'Y': return 34;
                case 'z': case 'Z': return 35;
                default:
                    throw new Exception("Could not decode MRZ character " + ch + " ('" + Char.ToString(ch) + "')");
            }
        }

    }
}
