import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Rainbow
import Progress

let ossindexURL = URL(string: "https://ossindex.sonatype.org/api/v3/component-report")!
var d:String, debug = false, dump_cache = false, clear_cache = false
var user:String?, pass:String?
var iqServerUrl:String?, iqServerAppId:String?
let fileManager = FileManager.default
let diskCacheConfig = DiskConfig(name: "speedbump", expiry: .date(Date().addingTimeInterval(12 * 3600)))
let memoryCacheConfig = MemoryConfig.init(expiry: .never, countLimit: 0, totalCostLimit: 0)
let storage = try? Storage(
    diskConfig: diskCacheConfig,
    memoryConfig: memoryCacheConfig,
    transformer: TransformerFactory.forCodable(ofType: VulnResult.self) // Storage<VulnResult>
)
var spinner = Spinner(pattern: .dots)

func printDebug(_ t:String) {
    if (debug) {
        print (t.blue())
    }
}

func printError(_ t:String) {
    print (t.red())
}

func pauseSpinner() {
    if spinner.isRunning {
        spinner.stop()
    }
}

func resumeSpinner() {
    if !spinner.isRunning {
        spinner.start()
    }
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
    spinner = Spinner(pattern: .dots)
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
        spinner.stopAndClear()
        return lockFiles
    }
    catch {
        spinner.fail(text: "Error enumerating files in directory \(dir): \(error).".red())
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

func getVulnDataFromApi(coords: [String]) -> [VulnResult] {
    var results:[VulnResult] = []
    let semaphore = DispatchSemaphore.init(value: 0)
    print("\(coords.count) package(s) to query API.")
    if coords.count == 0 {
        return []
    }
    let coordinates = ["coordinates": coords]
    let json = try! JSONSerialization.data(withJSONObject: coordinates)
    let sessionConfiguration = URLSessionConfiguration.default
    var request = URLRequest(url: ossindexURL)
    request.httpMethod = "POST"
    request.httpBody = json
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if (user != nil && pass != nil) {    
        print("Authenticating with user \(user!).")
        let loginString = "\(user!):\(pass!)"
        let loginData = loginString.data(using: String.Encoding.utf8)!
        let base64LoginString = loginData.base64EncodedString()
        request.setValue("Basic \(base64LoginString)", forHTTPHeaderField: "Authorization")
    }
    var apiData = Data(), apiResponse = ""
    let session = URLSession(configuration: sessionConfiguration)
    print("Querying OSSIndex API...".green())
    spinner = Spinner(pattern: .dots)
    spinner.start()
    let task = session.dataTask(with: request) {
        (data, response, error) in
        defer { semaphore.signal() }
        guard error == nil else {
            spinner.fail(text: "Error making POST request to \(ossindexURL): \(error!)")
            exit(1)
        }
        if (debug) {
            pauseSpinner()
            printDebug("HTTP request headers:")
            for (key, value) in request.allHTTPHeaderFields! {
                printDebug("\(key):\(value)")
            }
            resumeSpinner()
        }
        if let r = response as? HTTPURLResponse {
            pauseSpinner()
            printDebug("HTTP response headers:")
            printDebug("\(r.description)")
            resumeSpinner()
        }
        guard let responseData = data else {
            spinner.fail(text: "Error: did not receive response data.")
            exit(1)
        }
        let response = String(data: responseData, encoding: .utf8)!
        if !response.hasPrefix("[{\"coordinates\"")
        {
            spinner.fail(text: "Error: did not receive coordinate data in response \(response).")
            exit(1)
        }
        pauseSpinner()
        printDebug("HTTP response: \(response).")
        resumeSpinner()
        if (response == "") {
            spinner.fail(text: "Error: Empty response from server.")
            exit(1)
        }
        let jsonDecoder = JSONDecoder()
        do
        {
            results = try jsonDecoder.decode([VulnResult].self, from: responseData)
        }
        catch {
            spinner.fail(text: "Error decoding JSON response \(response): \(error).")
            exit(1)
        }
    }
    task.resume()
    if semaphore.wait(timeout: .now() + 15) == .timedOut {
        spinner.fail(text: "HTTP request timed out.")
        exit(1)
    }
    return results
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

func submitSBOM(coords: [String], sbom: String) {
    var app:Applications? = nil
    let semaphore = DispatchSemaphore.init(value: 0)
    if coords.count == 0 {
        return
    }
    let baseUrl = URL(string: iqServerUrl!)!
    let appidRequestUrl = URL(string: "/api/v2/applications?publicId=\(iqServerAppId!)", relativeTo: baseUrl)!
    printDebug("URL for request: \(appidRequestUrl.absoluteString).")
    var appidRequest = URLRequest(url: appidRequestUrl)
    let session = URLSession(configuration: URLSessionConfiguration.default)
    appidRequest.setValue("application/xml", forHTTPHeaderField: "Content-Type")
    appidRequest.httpMethod = "GET"
    let loginString = "\(user!):\(pass!)"
    let loginData = loginString.data(using: String.Encoding.utf8)!
    let base64LoginString = loginData.base64EncodedString()
    appidRequest.setValue("Basic \(base64LoginString)", forHTTPHeaderField: "Authorization")
    print("Authenticating with user \(user!).")
    print("Finding IQ Server internal id for app \(iqServerAppId!)...".green())
    spinner = Spinner(pattern: .dots)
    spinner.start()
    let appidtask = session.dataTask(with: appidRequest) {
        (data, response, error) in
        defer { semaphore.signal() }
        guard error == nil else {
            spinner.fail(text: "Error making GET request to \(appidRequestUrl.absoluteString): \(error!)")
            exit(1)
        }
        if (debug) {
            pauseSpinner()
            printDebug("HTTP request headers:")
            for (key, value) in appidRequest.allHTTPHeaderFields! {
                printDebug("    \(key):\(value)")
            }
            resumeSpinner()
        }
        if let r = response as? HTTPURLResponse {
            pauseSpinner()
            printDebug("HTTP response headers:")
            printDebug("    \(r.description)")
            resumeSpinner()
        }
        guard let responseData = data else {
            spinner.fail(text: "Error: did not receive response data.")
            exit(1)
        }
        pauseSpinner()
        printDebug("Response:\n \(responseData.debugDescription)")
        resumeSpinner()
        let jsonDecoder = JSONDecoder()
        do
        {
            app = try jsonDecoder.decode(Applications.self, from: responseData)
        }
        catch {
            spinner.fail(text: "Error decoding JSON response \(responseData.debugDescription): \(error).")
            exit(1)
        }
    }
    appidtask.resume()
    if semaphore.wait(timeout: .now() + 15) == .timedOut {
        spinner.stop(text: "HTTP request timed out.")
        exit(1)
    }
    let internalAppId = app!.applications![0].id!
    spinner.succeed(text: "Internal id for app id \(iqServerAppId!) is \(internalAppId).")
    spinner.stopAndClear()
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
        helpMessage: "(Optional) The OSS Index or IQ Server user for authentication.")
    let passOption = StringOption(shortFlag: "p", longFlag: "pass", required: false,
        helpMessage: "(Optional) The OSS Index or IQ Server password for authentication.")
    let iqServerUrlOption = StringOption(shortFlag: "s", longFlag: "server", required: false, 
        helpMessage: "(Optional) The Nexus IQ Server Url to submit a software BOM to.")
    let iqServerAppIdOption = StringOption(shortFlag: "i", longFlag: "appid", required: false,
        helpMessage: "(Optional) The Nexus IQ Server application id for the current Swift directory.")
    
    cli.addOptions(dirPathOption, debugOption, dumpCacheOption, clearCacheOption, userOption, passOption, iqServerUrlOption, iqServerAppIdOption)

    do {
        try cli.parse()
        let dir = dirPathOption.value
        debug = debugOption.value
        dump_cache = dumpCacheOption.value
        clear_cache = clearCacheOption.value
        user = userOption.value
        pass = passOption.value
        if debug {
            print("Debug output enabled.")
        }
        if (dump_cache || clear_cache) {
            return ""
        }
        if (!dump_cache && !clear_cache && (!dirPathOption.wasSet))
        {
            cli.printUsage()
        }
        if (iqServerUrlOption.wasSet && !(userOption.wasSet || passOption.wasSet)) {
            printError("You must specify a user name and password for calling the IQ Server API.")
            exit(2)
        }
        else if (iqServerUrlOption.wasSet && !iqServerAppIdOption.wasSet) {
            iqServerAppId = URL(fileURLWithPath: dir!).lastPathComponent
            print("Using \(iqServerAppId!) as the IQ Server app id.")
        }
        else if (iqServerAppIdOption.wasSet) {
            iqServerAppId = iqServerAppIdOption.value
        }

        if (iqServerUrlOption.wasSet) {
            iqServerUrl = iqServerUrlOption.value
            let url = URL(string: iqServerUrl!)
            if (url == nil || (url!.scheme != "http" && url!.scheme != "https")) {
                printError("The URL \(url!.debugDescription) is not valid.")
                exit(1)
            }            
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
    printError("You must specify a Swift project folder to audit using the -d or --dir option.")
    exit(2)
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
        spinner.stopAndClear()
        if (iqServerUrl != nil) {
            var xml:String = 
            """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <bom xmlns="http://cyclonedx.org/schema/bom/1.1" version="1" serialNumber="urn:uuid:d0a742e2-760d-47fb-a8e8-33bf37f6f105">
                <components>\n
            """
            for pin in p.object!.pins!
            {
                xml += "        <component type =\"library\">\n"
                xml += "            <name>\(pin.package!)</name>\n"
                xml += "            <version>\(pin.state!.version!)</version>\n"
                xml += "            <purl>pkg:swift/\(pin.package!)@\(pin.state!.version!)</purl>\n"
                xml += "        </component>\n"
            }
            xml += "    </components>\n"
            xml += "</bom>"
            if (debug) {                
                printDebug("Software BOM:\n\(xml)")
            } 
            submitSBOM(coords:_coords, sbom:xml)
            exit(0)
        }
        else {
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
            exit(0)
        }
    }
    else {
        printError("speedbump doesn't currently support package manager file \(f).")
        exit(3)
    }
}