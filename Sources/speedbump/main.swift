import Foundation
import FoundationNetworking
import Rainbow
import Progress

let ossindexURL = URL(string: "https://ossindex.sonatype.org/api/v3/component-report")!
let spinner = Spinner(pattern: .dots)
var d:String
var debug = false, dump_cache = false, clear_cache = false
var user:String?, pass:String?
let fileManager = FileManager.default
let diskCacheConfig = DiskConfig(name: "speedbump", expiry: .date(Date().addingTimeInterval(12 * 3600)))
let memoryCacheConfig = MemoryConfig.init(expiry: .never, countLimit: 0, totalCostLimit: 0)
let storage = try? Storage(
    diskConfig: diskCacheConfig,
    memoryConfig: memoryCacheConfig,
    transformer: TransformerFactory.forCodable(ofType: VulnResult.self) // Storage<VulnResult>
)

func printDebug(_ t:String) {
    if (debug) {
        print (t.yellow())
    }
}

func printError(_ t:String) {
    print (t.red())
}

func addResultToCache(purl:String, result:VulnResult) {
    guard let cache = storage else {
        return    
    }
    do
    {
        try cache.setObject(result, forKey: purl)
        printDebug("Added \(purl) to cache.")
    }
    catch {
        printError ("Could not write object to cache: \(error).")
    }
}

func getResultFromCache(purl: String) -> VulnResult? {
    guard let cache = storage else {
        return nil 
    }
    guard let entry = try? cache.entry(forKey: purl) else {
        return nil
    }
    return entry.object
}

func dumpCache() throws {
    let url = try fileManager.url(
        for: .cachesDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true
    )
    let path = url.appendingPathComponent("speedbump", isDirectory: true).path
    let storageURL = URL(fileURLWithPath: path)
    print("Cache directory is \(path).")
    let resourceKeys: [URLResourceKey] = [
        .isDirectoryKey,
        .contentModificationDateKey,
        .totalFileAllocatedSizeKey
    ]
    var resourceObjects = [ResourceObject]()
    var expiredEntries = [URL]()
    var totalSize: UInt = 0
    let fileEnumerator = fileManager.enumerator(
        at: storageURL,
        includingPropertiesForKeys: resourceKeys,
        options: .skipsHiddenFiles,
        errorHandler: nil
    )
    guard let urlArray = fileEnumerator?.allObjects as? [URL] else {
        return
    }
    print ("\(urlArray.count) package(s) in cache.")
    for url in urlArray {
        let resourceValues = try url.resourceValues(forKeys: Set(resourceKeys))
        guard resourceValues.isDirectory != true else {
            continue
        }

        if let expiryDate = resourceValues.contentModificationDate, expiryDate.inThePast {
            expiredEntries.append(url)
        }

        if let fileSize = resourceValues.totalFileAllocatedSize {
            totalSize += UInt(fileSize)
            resourceObjects.append((url: url, resourceValues: resourceValues))
        }
        print("Entry: \(url) Expires: \(resourceValues.contentModificationDate!).")
    }
}

func clearCache() throws {
    guard let cache = storage else {
        return
    }
    try cache.removeAll()
    try dumpCache()
}


class BasicAuthenticator: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate {
    
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        printDebug("heke")
    }

    func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        printDebug("heke")
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, 
       completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
           printDebug("heke")
    }
}

func getVulnDataFromApi(coords: [String]) -> [VulnResult] {
    var results:[VulnResult] = []
    let semaphore = DispatchSemaphore.init(value: 0)
    print("\(coords.count) package(s) to query API.")
    if coords.count == 0 {
        return []
    }
    let coordinates = ["coordinates": coords]
    print("Querying OSSIndex API...".green())
    let json = try! JSONSerialization.data(withJSONObject: coordinates)
    let sessionConfiguration = URLSessionConfiguration.default
    var request = URLRequest(url: ossindexURL)
    request.httpMethod = "POST"
    request.httpBody = json
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("\(json.count)", forHTTPHeaderField: "Content-Length")
    if (user != nil && pass != nil) {    
        print("Using user authentication \(user!).")
        let credential = URLCredential(user: user!, password: pass!, persistence: URLCredential.Persistence.forSession)
        let protectionSpace = URLProtectionSpace(host: "ossindex.sonatype.org", port: 443, protocol: "https", realm: "Sonatype OSS Index", authenticationMethod: NSURLAuthenticationMethodHTTPBasic)
        URLCredentialStorage.shared.setDefaultCredential(credential, for: protectionSpace)
        sessionConfiguration.urlCredentialStorage = URLCredentialStorage.shared //setDefaultCredential(credential, for: protectionSpace)
        // This block will set the auth header manually.
        //let loginString = "\(user!):\(pass!)"
        //let loginData = loginString.data(using: String.Encoding.utf8)!
        //let base64LoginString = loginData.base64EncodedString()
        //sessionConfiguration.httpAdditionalHeaders = ["Authorization": "Basic \(base64LoginString)"]
        //request.setValue("Basic \(base64LoginString)", forHTTPHeaderField: "Authorization")
    }
    spinner.start()
    var apiData = Data(), apiResponse = ""
    let session = URLSession.shared//(configuration: sessionConfiguration)//, delegate: BasicAuthenticator(), delegateQueue: nil)
    let task = session.dataTask(with: request) {
        (data, response, error) in
        defer { semaphore.signal() }
        guard error == nil else {
            spinner.stop()
            apiResponse = "error"
            printError("Error making POST request to \(ossindexURL): \(error!)")
            exit(1)
        }
        
        if (debug) {
            printDebug("HTTP request headers:")
            for (key, value) in request.allHTTPHeaderFields! {
                printDebug("\(key):\(value)")
            }
        }
        if let r = response as? HTTPURLResponse {
            printDebug("HTTP response headers:")
            printDebug("\(r.description)")
        }
        guard let responseData = data else {
            spinner.stop()
            apiResponse = "error"
            printError("Error: did not receive response data.")
            exit(1)
        }
        let response = String(data: responseData, encoding: .utf8)!
        if !response.hasPrefix("[{\"coordinates\"")
        {
            spinner.stop()
            apiResponse = "error"
            printError("Error: did not receive coordinate data in response \(response).")
            exit(1)
        }
        spinner.succeed(text: "Received \(responseData) from server.")
        printDebug("HTTP response: \(response).")
        if (response == "") {
            printError("Error: Empty response from server.")
            exit(1)
        }
        apiResponse = response
        apiData = responseData
        let jsonDecoder = JSONDecoder()
        do
        {
            results = try jsonDecoder.decode([VulnResult].self, from: apiData)
        }
        catch {
            printError("Error decoding JSON response \(apiResponse): \(error).")
            exit(1)
        }
    }
    task.resume()
    if semaphore.wait(timeout: .now() + 15) == .timedOut {
        spinner.stop()
        printError("HTTP request timed out.")
        exit(1)
    }
    return results
}

func printLogo() {
    let t = try? Figlet(fontFile:"fonts/chunky.flf")?.drawText(text: "SpeedBump")
    if let f = t {
        if let text = f {
            for s in text {
                print(s.lightGreen())
            }
        }
        else
        {
            print("Could not draw text.")
            print("SpeedBump".lightGreen())
        }
    }
    else {
        print("SpeedBump".lightGreen())
    }
    print ("v0.2.0\n".lightGreen())
}

func getLockFiles(dir: String) -> [String]
{
    spinner.start()
    do {
        if !FileManager.default.fileExists(atPath: dir) {
            printError ("The directory \(dir) does not exist.".red())
            exit(1)
        }
        var lockFiles = [String]()
        let fileURLs = try FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: dir), includingPropertiesForKeys: nil)
        for file in fileURLs {
            if file.pathExtension == "resolved" {
                lockFiles.append(file.path)
            }
        }
        spinner.succeed(text: "Found \(lockFiles.count) package manager file(s).")
        return lockFiles
    }
    catch {
        spinner.stop()
        print ("Error enumerating files in directory \(dir): \(error).".red())
        exit(1)
    }

}

func getSPMPackages(file: String) -> Packages
{
    let jsonDecoder = JSONDecoder()
    do
    {
	    return try jsonDecoder.decode(Packages.self,
            from: Data(contentsOf: URL(fileURLWithPath: file)))
    }
    catch {
        print ("Error reading JSON from file \(file): \(error).".red())
        exit(1)
    }
}

func printResults(results: [VulnResult])
{
    print("\nAudit Results")
    print ("=============\n")
    for result in results
    {
        let c = result.coordinates!.components(separatedBy: "/")
        let p = c[1].components(separatedBy: "@")
        let d = result.description ?? "None"
        let v = result.vulnerabilities ?? []

        print ("Package: \(p[0])\nVersion: \(p[1])\nDescription: \(d)")
        if (v == [])
        {
            print ("Not vulnerable\n".underline.green)
        }
        else
        {
            print ("Vulnerable: \(v)\n".red)
        }
    }
}

func parseCli() -> String? {
    let cli = CommandLine()
    cli.formatOutput = { s, type in
        var str: String
        switch(type) {
        case .error:
            str = s.red()
        case .optionFlag:
            str = s.green()
        case .optionHelp:
            str = s.blue()
        default:
            str = s.replacingOccurrences(of: ".build/debug/", with: "")
        }
        return cli.defaultFormat(s: str, type: type)
    }

    let dirPathOption = StringOption(shortFlag: "d", longFlag: "dir", required: false,
        helpMessage: "The Swift package directory to audit.")
    let debugOption = BoolOption(longFlag: "debug", required: false,
        helpMessage: "Enable debug output.")
    let dumpCacheOption = BoolOption(longFlag: "dump-cache", required: false,
        helpMessage: "Dump all cache entries")
    let clearCacheOption = BoolOption(longFlag: "clear-cache", required: false,
        helpMessage: "Clear cache.")
    let userOption = StringOption(shortFlag: "u", longFlag: "user", required: false,
        helpMessage: "(Optional) The OSS Index user for authentication.")
    let passOption = StringOption(shortFlag: "p", longFlag: "pass", required: false,
        helpMessage: "(Optional) The OSS Index password for authentication.")
    cli.addOptions(dirPathOption, debugOption, dumpCacheOption, clearCacheOption, userOption, passOption)

    do {
        try cli.parse()
        debug = debugOption.value
        dump_cache = dumpCacheOption.value
        clear_cache = clearCacheOption.value
        user = userOption.value
        pass = passOption.value
        if (!dump_cache && !clear_cache && (dirPathOption.value == nil))
        {
            cli.printUsage()
        }
        return dirPathOption.value
    }
    catch {
        print("Audit a Swift package's dependencies for security vulnerabilities.\n")
        cli.printUsage(error)
        exit(1)
    }
}

// CLI starts execution here
printLogo()
let dir = parseCli()
if debug {
    print("Debug output enabled.")
}
if dump_cache {
    do {
        try dumpCache()
        exit(0)
    } 
    catch {
        print("Error enumerating cache entries: \(error).")
        exit(1)   
    }
}
else if clear_cache {
    do {
        try clearCache()
        exit(0)
    }
    catch {
        printError ("Could not clear cache: \(error).")
        exit(1)
    }
}
else if dir == nil {
    exit(0)
}
else
{
    d = dir!
} 
let lockFiles = getLockFiles(dir: d)
if lockFiles.count == 0 {
    print ("Did not find any Swift dependency lock files in directory \(d)".red())
    exit(1)
}
for f in lockFiles {
    if f.hasSuffix("Package.resolved") {
        print("Using Swift Package Manager file \(f)...".green())
        spinner.start()
        let p = getSPMPackages(file: f)
        var coords = [String](), _coords = [String]()
        var cached = [VulnResult]()
        for pin in p.object!.pins! {
            _coords.append("pkg:swift/\(pin.package!)@\(pin.state!.version!)")
        }
        spinner.succeed(text: "Parsed \(p.object!.pins!.count) packages from \(f).")
        for (_, purl) in _coords.enumerated() {
            let c = getResultFromCache(purl: purl)
            if let r = c {
                cached.append(r)
                printDebug("Using cached entry for \(purl).")
            }
            else {
                coords.append(purl)
            }
        }
        print ("\(cached.count) cached package(s).")
        let results = getVulnDataFromApi(coords: coords)
        printResults(results: results + cached)
        for r in results {
            addResultToCache(purl: r.coordinates!, result: r)
        }
    }
    else {
        print("speedbump doesn't currently support package manager file \(f).".red())
    }
}