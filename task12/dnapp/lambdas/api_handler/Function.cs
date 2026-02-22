using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace SimpleLambdaFunction
{
    public class Function
    {
        private readonly ApiHandler _apiHandler;

        public Function()
        {
            _apiHandler = new ApiHandler();
        }

        public async Task<APIGatewayProxyResponse> FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            return await _apiHandler.HandleRequest(request, context);
        }
    }

    public class ApiHandler
    {
        private readonly AuthenticationService _authService;
        private readonly TablesService _tablesService;
        private readonly ReservationsService _reservationsService;

        public ApiHandler()
        {
            _authService = new AuthenticationService();
            _tablesService = new TablesService();
            _reservationsService = new ReservationsService();
        }

        public async Task<APIGatewayProxyResponse> HandleRequest(APIGatewayProxyRequest request, ILambdaContext context)
        {
            Console.WriteLine(JsonSerializer.Serialize(request));

            var method = (request.HttpMethod ?? string.Empty).ToUpperInvariant();
            var resource = request.Resource ?? string.Empty;

            if (resource == "/signup" && method == "POST") return await Signup(request);
            if (resource == "/signin" && method == "POST") return await Signin(request);
            if (resource == "/tables" && method == "POST") return await AddTable(request);

            var userSub = TryGetUserSub(request);
            if (string.IsNullOrWhiteSpace(userSub))
                return FormatResponse(401, new { message = "Unauthorized" });

            if (resource == "/tables" && method == "GET") return await GetTables();
            if (resource == "/tables/{tableId}" && method == "GET") return await GetTableById(request);
            if (resource == "/reservations" && method == "GET") return await GetReservations(userSub);
            if (resource == "/reservations" && method == "POST") return await CreateReservation(request, userSub);

            return FormatResponse(400,
                new
                {
                    message = $"Bad request syntax or unsupported method. Request path: {resource}. HTTP method: {method}"
                });
        }

        private static APIGatewayProxyResponse FormatResponse(int code, object response)
        {
            return new APIGatewayProxyResponse
            {
                StatusCode = code,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } },
                Body = JsonSerializer.Serialize(response),
                IsBase64Encoded = false
            };
        }

        private static T? ParseBody<T>(string? body)
        {
            if (string.IsNullOrWhiteSpace(body)) return default;
            try
            {
                return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch
            {
                return default;
            }
        }

        private static string? TryGetUserSub(APIGatewayProxyRequest request)
        {
            var auth = request.RequestContext?.Authorizer;
            if (auth is null) return null;

            // 1) REST API: authorizer["claims"] -> { "sub": "..." }
            if (auth.TryGetValue("claims", out var claimsObj))
            {
                var sub = TryGetSubFromClaimsObject(claimsObj);
                if (!string.IsNullOrWhiteSpace(sub)) return sub;
            }

            // 2) HTTP API JWT authorizer: authorizer["jwt"] -> { "claims": { "sub": "..." } }
            if (auth.TryGetValue("jwt", out var jwtObj) && jwtObj is IDictionary<string, object> jwtDict)
            {
                if (jwtDict.TryGetValue("claims", out var jwtClaimsObj))
                {
                    var sub = TryGetSubFromClaimsObject(jwtClaimsObj);
                    if (!string.IsNullOrWhiteSpace(sub)) return sub;
                }
            }

            // 3) Fallback
            if (auth.TryGetValue("principalId", out var principalId))
                return principalId?.ToString();

            return null;
        }

        private static string? TryGetSubFromClaimsObject(object claimsObj)
        {
            // Sometimes comes as IDictionary<string, object>
            if (claimsObj is IDictionary<string, object> dict && dict.TryGetValue("sub", out var subObj))
                return subObj?.ToString();

            // Sometimes comes as JsonElement in .NET Lambda
            if (claimsObj is JsonElement je)
            {
                if (je.ValueKind == JsonValueKind.Object && je.TryGetProperty("sub", out var subProp))
                    return subProp.GetString();
            }

            return null;
        }

        private static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        private sealed record SignUpBody(string FirstName, string LastName, string Email, string Password);
        private sealed record SignInBody(string Email, string Password);
        private sealed record AddTableBody(int? Id, int? Number, int? Places, bool? IsVip, int? MinOrder);
        private sealed record CreateReservationBody(int? TableId, string Date, string Slot, string? Notes);

        private async Task<APIGatewayProxyResponse> Signup(APIGatewayProxyRequest request)
        {
            var body = ParseBody<SignUpBody>(request.Body);
            if (body is null) return FormatResponse(400, new { message = "Invalid request body" });

            if (string.IsNullOrWhiteSpace(body.FirstName) ||
                string.IsNullOrWhiteSpace(body.LastName) ||
                string.IsNullOrWhiteSpace(body.Email) ||
                string.IsNullOrWhiteSpace(body.Password))
            {
                return FormatResponse(400, new { message = "firstName, lastName, email, password are required" });
            }

            if (!IsValidEmail(body.Email))
                return FormatResponse(400, new { message = "Invalid email" });

            try
            {
                var userSub = await _authService.SignUp(body.FirstName, body.LastName, body.Email, body.Password);
                return FormatResponse(200, new { userSub });
            }
            catch (UsernameExistsException)
            {
                return FormatResponse(400, new { message = "User already exists" });
            }
            catch (InvalidPasswordException ex)
            {
                return FormatResponse(400, new { message = ex.Message });
            }
            catch (InvalidParameterException ex)
            {
                return FormatResponse(400, new { message = ex.Message });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FormatResponse(400, new { message = "Signup failed" });
            }
        }

        private async Task<APIGatewayProxyResponse> Signin(APIGatewayProxyRequest request)
        {
            var body = ParseBody<SignInBody>(request.Body);
            if (body is null || string.IsNullOrWhiteSpace(body.Email) || string.IsNullOrWhiteSpace(body.Password))
                return FormatResponse(400, new { message = "email and password are required" });

            if (!IsValidEmail(body.Email))
                return FormatResponse(400, new { message = "Invalid email or password" });

            try
            {
                var auth = await _authService.SignIn(body.Email, body.Password);
                if (auth is null || string.IsNullOrWhiteSpace(auth.IdToken))
                    return FormatResponse(400, new { message = "Invalid email or password" });

                return FormatResponse(200, new
                {
                    token = auth.IdToken,
                    idToken = auth.IdToken,
                    accessToken = auth.AccessToken,
                    refreshToken = auth.RefreshToken,
                    expiresIn = auth.ExpiresIn,
                    tokenType = auth.TokenType
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FormatResponse(400, new { message = "Invalid email or password" });
            }
        }

        private async Task<APIGatewayProxyResponse> AddTable(APIGatewayProxyRequest request)
        {
            var body = ParseBody<AddTableBody>(request.Body);
            if (body is null) return FormatResponse(400, new { message = "Invalid request body" });

            var id = body.Id ?? Random.Shared.Next(10000, 99999);
            await _tablesService.AddTable(id, body.Number, body.Places, body.IsVip, body.MinOrder);
            return FormatResponse(200, new { id });
        }

        private async Task<APIGatewayProxyResponse> GetTables()
        {
            var tables = await _tablesService.GetTables();
            return FormatResponse(200, tables);
        }

        private async Task<APIGatewayProxyResponse> GetTableById(APIGatewayProxyRequest request)
        {
            if (request.PathParameters is null || !request.PathParameters.TryGetValue("tableId", out var tableId) || string.IsNullOrWhiteSpace(tableId))
                return FormatResponse(400, new { message = "tableId is required" });

            var table = await _tablesService.GetTableById(tableId);
            if (table is null)
                return FormatResponse(404, new { message = "Table not found" });

            return FormatResponse(200, table);
        }

        private async Task<APIGatewayProxyResponse> GetReservations(string userSub)
        {
            var reservations = await _reservationsService.GetReservations(userSub);
            return FormatResponse(200, reservations);
        }

        private async Task<APIGatewayProxyResponse> CreateReservation(APIGatewayProxyRequest request, string userSub)
        {
            var body = ParseBody<CreateReservationBody>(request.Body);
            if (body is null || body.TableId is null || string.IsNullOrWhiteSpace(body.Date) || string.IsNullOrWhiteSpace(body.Slot))
                return FormatResponse(400, new { message = "tableId, date, slot are required" });

            var id = await _reservationsService.CreateReservation(body.TableId.Value, body.Date, body.Slot, body.Notes, userSub);
            return FormatResponse(201, new { id });
        }
    }

    public class AuthenticationService
    {
        private readonly AmazonCognitoIdentityProviderClient _cognitoClient;
        private readonly string? _clientId = Environment.GetEnvironmentVariable("cup_client_id");
        private readonly string? _userPoolId = Environment.GetEnvironmentVariable("cup_id");

        public AuthenticationService()
        {
            _cognitoClient = new AmazonCognitoIdentityProviderClient();
        }

        public async Task<string> SignUp(string firstName, string lastName, string email, string password)
        {
            var signUpRequest = new SignUpRequest
            {
                ClientId = _clientId,
                Username = email,
                Password = password,
                UserAttributes = new List<AttributeType>
                {
                    new AttributeType { Name = "given_name", Value = firstName },
                    new AttributeType { Name = "family_name", Value = lastName },
                    new AttributeType { Name = "email", Value = email }
                }
            };

            var signUpResponse = await _cognitoClient.SignUpAsync(signUpRequest);

            await _cognitoClient.AdminConfirmSignUpAsync(new AdminConfirmSignUpRequest
            {
                UserPoolId = _userPoolId,
                Username = email
            });

            return signUpResponse.UserSub;
        }

        public async Task<AuthenticationResultType?> SignIn(string email, string password)
        {
            var authResponse = await _cognitoClient.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
                ClientId = _clientId,
                UserPoolId = _userPoolId,
                AuthParameters = new Dictionary<string, string>
                {
                    { "USERNAME", email },
                    { "PASSWORD", password }
                }
            });

            return authResponse.AuthenticationResult;
        }
    }

    public class TablesService
    {
        private readonly AmazonDynamoDBClient _ddb;
        private readonly string _tableName;

        public TablesService()
        {
            _ddb = new AmazonDynamoDBClient();
            _tableName = Environment.GetEnvironmentVariable("TABLES_TABLE") ??
                         Environment.GetEnvironmentVariable("tables_table") ??
                         throw new Exception("Missing TABLES_TABLE env var");
        }

        public async Task AddTable(int id, int? number, int? places, bool? isVip, int? minOrder)
        {
            var item = new Dictionary<string, AttributeValue>
            {
                ["id"] = new AttributeValue { S = id.ToString() }
            };

            if (number is not null) item["number"] = new AttributeValue { N = number.Value.ToString() };
            if (places is not null) item["places"] = new AttributeValue { N = places.Value.ToString() };
            if (isVip is not null) item["isVip"] = new AttributeValue { BOOL = isVip.Value };
            if (minOrder is not null) item["minOrder"] = new AttributeValue { N = minOrder.Value.ToString() };

            await _ddb.PutItemAsync(new PutItemRequest { TableName = _tableName, Item = item });
        }

        public async Task<List<Dictionary<string, object?>>> GetTables()
        {
            var resp = await _ddb.ScanAsync(new ScanRequest { TableName = _tableName });
            return resp.Items.Select(ToPlain).ToList();
        }

        public async Task<Dictionary<string, object?>?> GetTableById(string tableId)
        {
            var resp = await _ddb.GetItemAsync(new GetItemRequest
            {
                TableName = _tableName,
                Key = new Dictionary<string, AttributeValue>
                {
                    ["id"] = new AttributeValue { S = tableId }
                }
            });

            if (resp.Item is null || resp.Item.Count == 0)
                return null;

            return ToPlain(resp.Item);
        }

        private static Dictionary<string, object?> ToPlain(Dictionary<string, AttributeValue> item)
        {
            var result = new Dictionary<string, object?>();
            foreach (var (k, v) in item)
            {
                if (v.S != null) result[k] = v.S;
                else if (v.N != null) result[k] = int.TryParse(v.N, out var n) ? n : v.N;
                else if (v.NULL == true) result[k] = null;
                else result[k] = v.BOOL;
            }

            return result;
        }
    }

    public class ReservationsService
    {
        private readonly AmazonDynamoDBClient _ddb;
        private readonly string _tableName;

        public ReservationsService()
        {
            _ddb = new AmazonDynamoDBClient();
            _tableName = Environment.GetEnvironmentVariable("RESERVATIONS_TABLE") ??
                         Environment.GetEnvironmentVariable("reservations_table") ??
                         throw new Exception("Missing RESERVATIONS_TABLE env var");
        }

        public async Task<List<Dictionary<string, object?>>> GetReservations(string userSub)
        {
            var resp = await _ddb.ScanAsync(new ScanRequest
            {
                TableName = _tableName,
                FilterExpression = "#u = :u",
                ExpressionAttributeNames = new Dictionary<string, string> { ["#u"] = "userSub" },
                ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                {
                    [":u"] = new AttributeValue { S = userSub }
                }
            });

            return resp.Items.Select(ToPlain).ToList();
        }

        public async Task<string> CreateReservation(int tableId, string date, string slot, string? notes, string userSub)
        {
            var id = Guid.NewGuid().ToString("N");
            var item = new Dictionary<string, AttributeValue>
            {
                ["id"] = new AttributeValue { S = id },
                ["tableId"] = new AttributeValue { N = tableId.ToString() },
                ["date"] = new AttributeValue { S = date },
                ["slot"] = new AttributeValue { S = slot },
                ["userSub"] = new AttributeValue { S = userSub },
                ["createdAt"] = new AttributeValue { S = DateTimeOffset.UtcNow.ToString("O") }
            };

            if (!string.IsNullOrWhiteSpace(notes))
                item["notes"] = new AttributeValue { S = notes };

            await _ddb.PutItemAsync(new PutItemRequest { TableName = _tableName, Item = item });
            return id;
        }

        private static Dictionary<string, object?> ToPlain(Dictionary<string, AttributeValue> item)
        {
            var result = new Dictionary<string, object?>();
            foreach (var (k, v) in item)
            {
                if (v.S != null) result[k] = v.S;
                else if (v.N != null) result[k] = int.TryParse(v.N, out var n) ? n : v.N;
                else if (v.NULL == true) result[k] = null;
                else result[k] = v.BOOL;
            }

            return result;
        }
    }
}
