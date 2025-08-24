using Chaos.NaCl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace ConfigCooker;

public class Program
{
    private static string SigningKey = string.Empty;
    private static string SigningKeyName = string.Empty;
    private static string PublicKey = string.Empty;
    private static ulong Timestamp;

    public static void Main(string[] args)
    {
        if (!File.Exists("signing.key"))
        {
            byte[] newKey = RandomNumberGenerator.GetBytes(32);
            SigningKey = Convert.ToBase64String(newKey);
            File.WriteAllText("signing.key", SigningKey);
            File.WriteAllText("public.key", PublicKey);
            Console.WriteLine($"Generated new key {SigningKeyName} and saved to signing.key");
        }
        else
        {
            SigningKey = File.ReadAllText("signing.key").Trim();
        }

        PublicKey = Convert.ToBase64String(Ed25519.PublicKeyFromSeed(Convert.FromBase64String(SigningKey)));
        SigningKeyName = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(PublicKey))[0..4]);
        Timestamp = (ulong)(DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds;

        // --- sanity check

        if (Convert.FromBase64String(SigningKey).Length != 32)
            throw new Exception("Signing key is not 32 bytes");

        string test = SignMessage("Testing", 123, SigningKey);

        bool testResult1 = VerifyMessage("Testing", 123, test, PublicKey);
        bool testResult2 = VerifyMessage("Testinx", 123, test, PublicKey);
        bool testResult3 = VerifyMessage("Testing", 1234, test, PublicKey);

        if (!testResult1)
            throw new Exception("Failed to verify testing message");

        if (testResult2 || testResult3)
            throw new Exception("Verified a tampered message");

        // ---

        var configIn = JsonNode.Parse(File.ReadAllText("input.json")) as JsonObject;

        if (configIn == null)
            throw new Exception("config input is not a json object");

        // ---

        JsonSerializerOptions rootJsonOpts = new()
        {
            WriteIndented = true,
        };

        string configString = JsonSerializer.Serialize(configIn, new JsonSerializerOptions()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
        });

        JsonObject root = new()
        {
            { "ts", Timestamp },
            { "config", configString },
        };

        Console.WriteLine($"Signing with key {SigningKeyName}");

        // todo: multi-sig
        // only implements a single signature right now

        JsonObject sigObj = new()
        {
            { SigningKeyName, SignMessage(configString, Timestamp, SigningKey) }
        };

        root.Add("sig", sigObj);

        // ---

        string jsonString = JsonSerializer.Serialize(root, rootJsonOpts).Replace("\\u0022", "\\\"").Replace("\\u002B", "+");

        var file = File.OpenWrite("config.json");
        file.SetLength(0);
        file.Write(UTF8Encoding.UTF8.GetBytes(jsonString));
        Console.WriteLine($"Wrote {file.Position} bytes to config.json");
        file.Dispose();
    }

    private static JsonObject MakeSignedConfig<T>(T config)
    {
        JsonSerializerOptions jsonOpts = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
        };
        string configString = JsonSerializer.Serialize(config, jsonOpts);
        return new JsonObject
        {
            { "data", configString },
            { "sig", SignMessage(configString, Timestamp, SigningKey) }
        };
    }

    private static string SignMessage(string message, ulong ts, string key)
    {
        byte[] msg = [.. BitConverter.GetBytes(ts), .. UTF8Encoding.UTF8.GetBytes(message)];
        byte[] priv = Ed25519.ExpandedPrivateKeyFromSeed(Convert.FromBase64String(SigningKey));
        byte[] sig = Ed25519.Sign(msg, priv);
        return Convert.ToBase64String(sig);
    }

    private static bool VerifyMessage(string message, ulong ts, string signature, string pubKey)
    {
        byte[] msg = [.. BitConverter.GetBytes(ts), .. UTF8Encoding.UTF8.GetBytes(message)];
        byte[] sig = Convert.FromBase64String(signature);
        byte[] pub = Convert.FromBase64String(pubKey);
        return Ed25519.Verify(sig, msg, pub);
    }
}