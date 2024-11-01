using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using SymmetricEncryptionAPI.Helpers;
using SymmetricEncryptionAPI.Models;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace SymmetricEncryptionAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly AesEncryption _aesEncryption; // Assuming you have an AesEncryption class similar to what you've provided
        private readonly IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            _configuration=configuration;
            _aesEncryption = new AesEncryption(_configuration["JWT:key"]); // Use a consistent key here
        }

        [HttpPost("login")]
        public ActionResult<RequestModel> Login([FromBody] RequestModel request)
        {
            try
            {
                // Decrypt the incoming data
                var decryptedData = _aesEncryption.Decrypt(request.data);

                // Deserialize decrypted data to a Login object
                var login = JsonConvert.DeserializeObject<Login>(decryptedData);

                // Check if login data is null
                if (login == null)
                {
                    return NotFound(new { message = "Login data not found." });
                }

                // Validate the model state
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid model state." });
                }

                // Validate email and password
                if (login.Email != "mjm@gmail.com" || login.Password != "Mjm@123#")
                {
                    return BadRequest(new { message = "Invalid email or password." });
                }

                // Serialize and encrypt the response data
                var loginData = JsonConvert.SerializeObject(login);
                var response = _aesEncryption.Encrypt(loginData); // Encrypt response data

                // Return encrypted response
                return Ok(new { encryptedResponse = response, message = "Login successful." });
            }
            catch (JsonSerializationException jsonEx)
            {
                // Handle deserialization errors
                return BadRequest(new { message = "Error parsing JSON data.", error = jsonEx.Message });
            }
            catch (CryptographicException cryptoEx)
            {
                // Handle encryption/decryption errors
                return StatusCode(500, new { message = "Encryption/Decryption error.", error = cryptoEx.Message });
            }
            catch (Exception ex)
            {
                // Handle any other unexpected errors
                return StatusCode(500, new { message = "An unexpected error occurred.", error = ex.Message });
            }
        }

    }
}
