import 'dart:io';
import 'dart:math';
import 'dart:json' as JSON;
import 'dart:async';
import 'dart:utf';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import "package:html5lib/dom.dart";
import "package:fukiya/fukiya.dart";
import "package:google_plus_v1_api/plus_v1_api_console.dart" as plus;
import "package:google_plus_v1_api/plus_v1_api_client.dart" as plus_client;
import "package:google_mirror_v1_api/mirror_v1_api_console.dart" as mirror;
import "package:google_mirror_v1_api/mirror_v1_api_client.dart" as mirror_client;
import "package:google_oauth2_client/google_oauth2_console.dart" as console_auth;
import "package:logging/logging.dart";

final String CLIENT_ID = "327285194570-kbpkgvfe87tlvpue69lf5krdokbepo6j.apps.googleusercontent.com";
final String CLIENT_SECRET = "G6KLdY07klgrDKT2jcAYVE45";

final String TOKENINFO_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo";
final String TOKEN_ENDPOINT = 'https://accounts.google.com/o/oauth2/token';
final String TOKEN_REVOKE_ENDPOINT = 'https://accounts.google.com/o/oauth2/revoke';

final String INDEX_HTML = "./web/index.html";
final Random random = new Random();
final Logger serverLogger = new Logger("server");

void main() {
  _setupLogger();

  new Fukiya()
  ..get('/', getIndexHandler)
  ..get('/index.html', getIndexHandler)
  ..get('/index', getIndexHandler)
  ..post('/connect', postConnectDataHandler)
  ..get('/people', getPeopleHandler)
  ..post('/disconnect', postDisconnectHandler)
  ..post('/insertItem', postMirrorInsertItem)
  ..staticFiles('./web')
  ..use(new FukiyaJsonParser())
  ..listen('127.0.0.1', 3333);
}

void postMirrorInsertItem(FukiyaContext context) {
  //http://www.glassfrogger.com/img/cartoon_frog_big.png
  serverLogger.fine("postMirrorInsertItem");
  String accessToken = context.request.session.containsKey("access_token") ? context.request.session["access_token"] : null;
  print("accessToken = ${accessToken}");
  SimpleOAuth2 simpleOAuth2 = new SimpleOAuth2()..credentials = new console_auth.Credentials(accessToken);
  mirror.Mirror _mirror = new mirror.Mirror(simpleOAuth2);
  _mirror.makeAuthRequests = true;

  String html = """
<article class="photo cover-only">  
  <img src="http://www.glassfrogger.com/img/cartoon_frog_big.png" height="100%" width="100%">  
  <div class="photo-overlay"></div>  
  <section>    
    <p class="text-auto-size">
      <strong class="white">Google Glass</strong> 
      <em class="blue">Dartified!</em>
    </p>  
  </section>
  <footer>    
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABUAAAAVCAMAAACeyVWkAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAJxQTFRFAAAAAIvMdsvDAIvMdsvDAIvMdsvDLaTJAIvMOqnHdsvDAIvMdsvDAIvMKaLJdsvDAIvMAIvMdsvDAIvMdsvDdsvDAIvMAIvMAZnFdsvDAILHAIPHAITIAIXJAIfKAIjKAIrLAIrMAIvMAJXHAJjFC5i/I6HENr2yOb6zPr+0TsK4UsO5WbnEWcW8Xsa9Yse+Zsi/asjAc8rCdsvDdt4SRQAAABp0Uk5TABAQICAwMFBgYGBwcICAgI+vr7+/z9/v7+97IXGnAAAAqUlEQVQYV13QxxaCQBBE0VZkjBgAGVEBaVEUM/P//yaTGg5vV3dZANTCZ9BvFAoR93kVC9FnthW6uIPTJ7UkdHaXvS2LXKNBURInyDXPsShbzjU7XCpxhooDVGo5QcQAJmjUco64AY/UcIrowYCTaj5KBZeTaj5JBTc6l11OlQKMf497y1ahefFb3TQfcqtM/fipJF/X9gnDon6/ah/aDDfNOgosNA2b8QdGciZlh/U93AAAAABJRU5ErkJggg==" class="left">  

    <p>Dart Hacking</p>   
  </footer> 
</article>

<article class="auto-paginate">  
  <ol class="text-x-small">  
  <strong>Instructions:</strong>
  <hr>  
    <li>First item</li>    
    <li>Second item</li>    
    <li>Third item</li>    
    <li>Fourth item</li>  
  </ol>
</article>
""";

  mirror_client.NotificationConfig notification = new mirror_client.NotificationConfig.fromJson({});
  notification.level = "DEFAULT";
  mirror_client.MenuItem menuItem = new mirror_client.MenuItem.fromJson({});
  menuItem.action = "VIEW_WEBSITE";
  menuItem.payload = "http://www.google.com";

  mirror_client.TimelineItem timeLineItem = new mirror_client.TimelineItem.fromJson({});
  timeLineItem.menuItems = [menuItem];
  timeLineItem.html = html;
  timeLineItem.notification = notification;
  _mirror.timeline.insert(timeLineItem)
  .then((mirror_client.TimelineItem updatedItem) {
        print("updatedItem = ${updatedItem.toString()}");
        context.send(updatedItem.toString());
      },
      onError: (error) => print("error = $error"));
}

/**
 * Revoke current user's token and reset their session.
 */
void postDisconnectHandler(FukiyaContext context) {
  serverLogger.fine("postDisconnectHandler");
  serverLogger.fine("context.request.session = ${context.request.session}");

  String tokenData = context.request.session.containsKey("access_token") ? context.request.session["access_token"] : null;
  if (tokenData == null) {
    context.response.statusCode = 401;
    context.send("Current user not connected.");
    return;
  }

  final String revokeTokenUrl = "${TOKEN_REVOKE_ENDPOINT}?token=${tokenData}";
  context.request.session.remove("access_token");

  new http.Client()..get(revokeTokenUrl).then((http.Response response) {
    serverLogger.fine("GET ${revokeTokenUrl}");
    serverLogger.fine("Response = ${response.body}");
    context.request.session["state_token"] = _createStateToken();
    Map data = {
                "state_token": context.request.session["state_token"],
                "message" : "Successfully disconnected."
                };
    context.send(JSON.stringify(data));
  });
}

/**
 * Get list of people user has shared with this app.
 */
void getPeopleHandler(FukiyaContext context) {
  serverLogger.fine("getPeopleHandler");
  String accessToken = context.request.session.containsKey("access_token") ? context.request.session["access_token"] : null;
  SimpleOAuth2 simpleOAuth2 = new SimpleOAuth2()..credentials = new console_auth.Credentials(accessToken);
  plus.Plus plusclient = new plus.Plus(simpleOAuth2);
  plusclient.makeAuthRequests = true;
  plusclient.people.list("me", "visible").then((plus_client.PeopleFeed people) {
    serverLogger.fine("/people = $people");
    context.send(people.toString());
  });
}

/**
 * Upgrade given auth code to token, and store it in the session.
 * POST body of request should be the authorization code.
 * Example URI: /connect?state=...&gplus_id=...
 */
void postConnectDataHandler(FukiyaContext context) {
  serverLogger.fine("postConnectDataHandler");
  String tokenData = context.request.session.containsKey("access_token") ? context.request.session["access_token"] : null; // TODO: handle missing token
  String stateToken = context.request.session.containsKey("state_token") ? context.request.session["state_token"] : null;
  String queryStateToken = context.request.uri.queryParameters.containsKey("state_token") ? context.request.uri.queryParameters["state_token"] : null;

  // Check if the token already exists for this session.
  if (tokenData != null) {
    context.send("Current user is already connected.");
    return;
  }

  // Check if any of the needed token values are null or mismatched.
  if (stateToken == null || queryStateToken == null || stateToken != queryStateToken) {
    context.response.statusCode = 401;
    context.send("Invalid state parameter.");
    return;
  }

  // Normally the state would be a one-time use token, however in our
  // simple case, we want a user to be able to connect and disconnect
  // without reloading the page.  Thus, for demonstration, we don't
  // implement this best practice.
  context.request.session.remove("state_token");

  String gPlusId = context.request.uri.queryParameters["gplus_id"];
  StringBuffer sb = new StringBuffer();
  // Read data from request.
  context.request
  .transform(new Utf8DecoderTransformer())
  .listen((data) => sb.write(data), onDone: () {
    serverLogger.fine("context.request.listen.onDone = ${sb.toString()}");
    Map requestData = JSON.parse(sb.toString());

    Map fields = {
              "grant_type": "authorization_code",
              "code": requestData["code"],
              // http://www.riskcompletefailure.com/2013/03/postmessage-oauth-20.html
              "redirect_uri": "postmessage",
              "client_id": CLIENT_ID,
              "client_secret": CLIENT_SECRET
    };

    serverLogger.fine("fields = $fields");
    http.Client _httpClient = new http.Client();
    _httpClient.post(TOKEN_ENDPOINT, fields: fields).then((http.Response response) {
      // At this point we have the token and refresh token.
      var credentials = JSON.parse(response.body);
      serverLogger.fine("credentials = ${response.body}");
      _httpClient.close();

      var verifyTokenUrl = '${TOKENINFO_URL}?access_token=${credentials["access_token"]}';
      new http.Client()
      ..get(verifyTokenUrl).then((http.Response response)  {
        serverLogger.fine("response = ${response.body}");

        var verifyResponse = JSON.parse(response.body);
        String userId = verifyResponse.containsKey("user_id") ? verifyResponse["user_id"] : null;
        String accessToken = credentials.containsKey("access_token") ? credentials["access_token"] : null;
        if (userId != null && userId == gPlusId && accessToken != null) {
          context.request.session["access_token"] = accessToken;
          context.send("POST OK");
        } else {
          context.response.statusCode = 401;
          context.send("POST FAILED ${userId} != ${gPlusId}");
        }
      });
    });
  });
}

/**
 * Sends the client a index file with state token and starts the client
 * side authentication process.
 */
void getIndexHandler(FukiyaContext context) {
  serverLogger.fine("getIndexHandler");
  // Create a state token.
  context.request.session["state_token"] = _createStateToken();

  // Readin the index file and add state token into the meta element.
  var file = new File(INDEX_HTML);
  file.exists().then((bool exists) {
    if (exists) {
      file.readAsString().then((String indexDocument) {
        Document doc = new Document.html(indexDocument);
        Element metaState = new Element.html('<meta name="state_token" content="${context.request.session["state_token"]}">');
        doc.head.children.add(metaState);
        context.response.write(doc.outerHtml);
        context.response.done.catchError((e) => serverLogger.fine("File Response error: ${e}"));
        context.response.close();
      }, onError: (error) => serverLogger.fine("error = $error"));
    } else {
      context.response.statusCode = 404;
      context.response.close();
    }
  });
}

/**
 * Creating state token based on random number.
 */
String _createStateToken() {
  StringBuffer stateTokenBuffer = new StringBuffer();
  new MD5()
  ..add(random.nextDouble().toString().codeUnits)
  ..close().forEach((int s) => stateTokenBuffer.write(s.toRadixString(16)));
  String stateToken = stateTokenBuffer.toString();
  return stateToken;
}

/**
 * Logger configuration.
 */
_setupLogger() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((LogRecord logRecord) {
    StringBuffer sb = new StringBuffer();
    sb
    ..write(logRecord.time.toString())..write(":")
    ..write(logRecord.loggerName)..write(":")
    ..write(logRecord.level.name)..write(":")
    ..write(logRecord.sequenceNumber)..write(": ")
    ..write(logRecord.message.toString());
    print(sb.toString());
  });
}

/**
 * Simple OAuth2 class for making requests and storing credentials in memory.
 */
class SimpleOAuth2 implements console_auth.OAuth2Console {
  final Logger logger = new Logger("SimpleOAuth2");

  Uri _tokenEndpoint = Uri.parse(
      'https://accounts.google.com/o/oauth2/token');
  Uri get tokenEndpoint => _tokenEndpoint;

  console_auth.Credentials _credentials;
  console_auth.Credentials get credentials => _credentials;
  void set credentials(value) {
    _credentials = value;
  }
  console_auth.SystemCache _systemCache;
  console_auth.SystemCache get systemCache => _systemCache;

  void clearCredentials(console_auth.SystemCache cache) {
    logger.fine("clearCredentials(console_auth.SystemCache $cache)");
  }

  Future withClient(Future fn(console_auth.Client client)) {
    logger.fine("withClient(Future ${fn}(console_auth.Client client))");
    console_auth.Client _httpClient = new console_auth.Client(CLIENT_ID, CLIENT_SECRET, _credentials);
    return fn(_httpClient);
  }

  void close() {
    logger.fine("close()");
  }
}