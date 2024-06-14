var hm = require('header-metadata');
var sm = require('service-metadata');
const crypto = require("crypto");
var headers = hm.current;
var path = sm.getVar('var://service/URI');
console.notice('path:\n' +  path);
if (path.includes('/paycollect/api/v1/banks/VPBKVNVX/funds_transfers/')) {
// Read the input as a JSON object

  session.input.readAsJSON(function (error, json) {

    if (error) {
      throw error;
    }
    console.notice('Orgin Header: '+  JSON.stringify(headers) + '\nand Body payload:\n' + JSON.stringify(json));
    var uri = sm.getVar('var://service/URL-out');
    var httpmethod = sm.getVar('var://service/protocol-method');

    var currentDateWithFormat = new Date().toISOString().slice(0,10).replace(/-/g,"");
    currentDateWithFormat  = '20240613';
    console.notice('currentDateWithFormat: '+  currentDateWithFormat);
    var currentDateTimeWithFormat = new Date().toISOString().replace(/[-:.]/g, "").replace("T", "").replace("Z", "Z");
    console.notice('currentDateTimeWithFormat: '+  currentDateTimeWithFormat);
    var payload = headers.get('payCollect');

    const algorithm = 'OWS1-HMAC-SHA256';
    const accessKeyId = 'VPB';
    const secretAccessKey= 'A57525892B2E40A8845E201BF0114BBF';
    const region = 'onepay';
    const service = 'paycollect';
    const terminator = 'ows1_request';
    const httpMethod = 'PUT';
    const UriInSign = '/paycollect/api/v1/banks/VPBKVNVX/funds_transfers/';
    const requestParam = '';
     
    var credential = accessKeyId + '/' + currentDateWithFormat + '/' + region + '/' + service + '/' + terminator ;
    console.notice('credential: '+  credential);
    var scope = currentDateWithFormat + '/' + region + '/' + service + '/' + terminator  ;
    console.notice('scope: '+  scope);
    var signedHeader  = 'x-op-date;x-op-expires';

    
    var hash = crypto.createHash('sha256');
    var payLoadHash = hash.update(payload).digest('hex').toLowerCase();
    console.notice('payLoadHash: '+  payLoadHash);
    //why need \n\n   ??
    var canonicalRequest = httpMethod + '\n' + UriInSign + '\n' + requestParam + '\n' + 'x-op-date:' +  currentDateTimeWithFormat + '\n' + 'x-op-expires:300\n' + '\n' + signedHeader + '\n' + payLoadHash ;
    console.notice('canonicalRequest: '+  canonicalRequest);
    var hashCanon = crypto.createHash('sha256');
    var canonicalRequestHash = hashCanon.update(canonicalRequest).digest('hex').toLowerCase();
    console.notice('canonicalRequestHash: '+  canonicalRequestHash);
    
    var stringToSign = algorithm + '\n' + currentDateTimeWithFormat + '\n' + scope + '\n' + canonicalRequestHash;
    console.notice('stringToSign: '+  stringToSign);
    var secretKeyStep1 = new Buffer(36);
    secretKeyStep1.write('OWS1' + secretAccessKey);
    console.notice('FirstKey: '+  'OWS1' + secretAccessKey);
    var hmacKeyTime = crypto.createHmac('hmac-sha256', secretKeyStep1);
    var dateKey = hmacKeyTime.update(currentDateWithFormat).digest("hex").toLowerCase();
    console.notice('dateKey: '+  dateKey);

    const secretKeyStep2 = Buffer.from(dateKey, 'hex');
    var hmacKeyRegion = crypto.createHmac('hmac-sha256', secretKeyStep2);
    var dateRegionKey = hmacKeyRegion.update(region).digest("hex").toLowerCase();
    console.notice('dateRegionKey: '+  dateRegionKey);

    const secretKeyStep3 = Buffer.from(dateRegionKey, 'hex');
    var hmacKeyService = crypto.createHmac('hmac-sha256', secretKeyStep3);
    var dateRegionServiceKey = hmacKeyService.update(service).digest("hex").toLowerCase();
    console.notice('dateRegionServiceKey: '+  dateRegionServiceKey);

    const secretKeyStep4 = Buffer.from(dateRegionServiceKey, 'hex');
    var hmacKeySign = crypto.createHmac('hmac-sha256', secretKeyStep4);
    var dateRegionServiceTerminatorKey = hmacKeySign.update(terminator).digest('hex').toLowerCase();
    console.notice('dateRegionServiceTerminatorKey: '+  dateRegionServiceTerminatorKey);

    const secretKeyStep5 = Buffer.from(dateRegionServiceTerminatorKey, 'hex');
    var hmacKeySign = crypto.createHmac('hmac-sha256', secretKeyStep5);
    var finalAuthorization = hmacKeySign.update(stringToSign).digest('hex').toLowerCase();
    console.notice('finalAuthorization: '+  finalAuthorization);

    var authorization = algorithm + ' Credential=' + accessKeyId + '/' + currentDateWithFormat + '/' + region + '/' + service + '/' + terminator + ',SignedHeaders=x-op-date;x-op-expires,Signature=' + finalAuthorization;
    console.notice('authorization: '+  authorization);
    //Set header
    headers.set('X-OP-Date', currentDateTimeWithFormat);
    headers.set('X-OP-Expires', '300');
    headers.set('X-OP-Authorization', authorization);

    console.notice('Final request to backend URL : ' + sm.URLOut + '\nWith Header params:\n' +  JSON.stringify(headers) + '\nand Body payload:\n' + JSON.stringify(json));
    session.output.write(json);
  });


} else {
	console.error('API: ' + path + ' Not supported!');
}
