import Foundation
import FoundationNetworking
import Rainbow
import Progress

let ossindexURL = URL(string: "https://ossindex.sonatype.org/api/v3/component-report")!
let spinner = Spinner(pattern: .dots)
var debug = false, dump_cache = false, clear_cache = false
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
        print("Entry: \(url)")
    }
    
    // Remove expired objects
    //for url in filesToDelete {
    //try fileManager.removeItem(at: url)
    //onRemove?(url.path)
    //}

    // Remove objects if storage size exceeds max size
    //try removeResourceObjects(resourceObjects, totalSize: totalSize)
    
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

func parseCli() -> String{
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

    let dirPath = StringOption(shortFlag: "d", longFlag: "dir", required: true,
        helpMessage: "The Swift package directory to audit.")
    let debugOption = BoolOption(longFlag: "debug", required: false,
        helpMessage: "Enable debug output.")
    let dumpCacheOption = BoolOption(longFlag: "dump-cache", required: false,
        helpMessage: "Dump all cache entries")
    let clearCacheOption = BoolOption(longFlag: "clear-cache", required: false,
        helpMessage: "Clear cache.")
    cli.addOptions(dirPath, debugOption, dumpCacheOption, clearCacheOption)

    do {
        try cli.parse()
        debug = debugOption.value
        dump_cache = dumpCacheOption.value
        clear_cache = clearCacheOption.value
        return dirPath.value!
    }
    catch {
        print("Audit a Swift package's dependencies for security vulnerabilities.\n")
        cli.printUsage(error)
        exit(1)
    }
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

// CLI starts execution here
printLogo()
let d = parseCli()
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
        var coords = [String]()
        var cached = [VulnResult]()
        for pin in p.object!.pins! {
            coords.append("pkg:swift/\(pin.package!)@\(pin.state!.version!)")
        }
        for (index, purl) in coords.enumerated() {
            let c = getResultFromCache(purl: purl)
            if let r = c {
                coords.remove(at: index)
                cached.append(r)
                printDebug("Using cached entry for \(purl).")
            }
        }
        let coordinates = ["coordinates": coords]
        spinner.succeed(text: "Parsed \(p.object!.pins!.count) packages from \(f).")
        print("Querying OSSIndex API...".green())
        spinner.start()
        let json = try! JSONSerialization.data(withJSONObject: coordinates)
        var request = URLRequest(url: ossindexURL)
        request.httpMethod = "POST"
        request.httpBody = json
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("\(json.count)", forHTTPHeaderField: "Content-Length")
        var apiData = Data()
        var apiResponse = ""
        let session = URLSession.shared
        let task = session.dataTask(with: request) {
            (data, response, error) in
            guard error == nil else {
                spinner.stop()
                printError("Error making POST request to \(ossindexURL)")
                exit(1)
            }
            guard let responseData = data else {
                spinner.stop()
                printError("Error: did not receive response data.")
                exit(1)
            }
            let response = String(data: responseData, encoding: .utf8)!
            printDebug("HTTP response: \(response).")
            if !response.hasPrefix("[{\"coordinates\"")
            {
                spinner.stop()
                printError("Error: did not receive coordinate data in response \(response).")
                exit(1)
            }
            spinner.succeed(text: "Received \(responseData) from server.")

            apiResponse = response
            if (apiResponse == "") {
              printError("Error: Empty response from server.")
              exit(1)
            }
            apiData = responseData
            print ("Data retrieved")
            print (responseData)
        }
        task.resume()
        while ((task.state == .running) || (apiResponse == "")) {}

        let jsonDecoder = JSONDecoder()
        do
        {
	        let results = try jsonDecoder.decode([VulnResult].self, from: apiData)
            printResults(results: results)
            for r in results {
                addResultToCache(purl: r.coordinates!, result: r)
            }
        }
        catch {
            printError("Error decoding JSON \(apiResponse): \(error).")
            exit(1)
        }

    }
    else {
        print("speedbump doesn't currently support package manager file \(f).".red())
    }
}