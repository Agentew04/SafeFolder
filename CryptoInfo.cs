using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeFolder
{
    public class CryptoInfo{

        /// <summary>
        /// sha256 hash of the file, store in base64
        /// </summary>
        /// <value>sha256 hash of the file, store in base64</value>
        [JsonPropertyName("sha256")]
        public string hash {get;set;}

        //File Name
        [JsonPropertyName("name")]
        public string FileName{get;set;}

        //File Extension
        [JsonPropertyName("ext")]
        public string Extension{get;set;}

        //encryption iv
        [JsonPropertyName("iv")]
        public byte[] iv{get;set;}

        public override string ToString()
        {
            return JsonSerializer.Serialize(this);
        }
    }
}
