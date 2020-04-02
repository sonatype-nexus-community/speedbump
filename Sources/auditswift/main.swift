import Foundation
import FoundationNetworking
import Rainbow
import Progress

let ossindexURL = URL(string: "https://ossindex.sonatype.org/api/v3/component-report")!
let spinner = Spinner(pattern: .dots)
var debug = false
let diskCacheConfig = DiskConfig(name: "speedbump", expiry: .date(Date().addingTimeInterval(12 * 3600)))
let memoryCacheConfig = MemoryConfig.init(expiry: .never, countLimit: 0, totalCostLimit: 0)
let storage = try? Storage(
    diskConfig: diskCacheConfig,
    memoryConfig: memoryCacheConfig,
    transformer: TransformerFactory.forCodable(ofType: VulnResult.self) // Storage<VulnResult>
    )

func addResultToCache(purl:String, result:VulnResult) {
    guard let cache = storage else {
        return    
    }
    do
    {
        try cache.setObject(result, forKey: purl)
    }
    catch {
        print ("Could not write object to cache: \(error).")
    }
}

func getResultFromCache(purl: String) -> VulnResult?
{
    guard let cache = storage else {
        return nil 
    }
    guard let entry = try? cache.entry(forKey: purl) else {
        return nil
    }
    return entry.object
}
func printLogo() {
    let t = try? Figlet(fontFile:"fonts/chunky.flf")?.drawText(text: "SpeedBump")
    if let f = t {
        if let text = f {
            for s in text {
                print(s)
            }
        }
        else
        {
            print("Could not draw text.")
            print("AuditSwift")
        }
    }
    else {
        print("AuditSwift")
    }
    print ("v0.1.0\n")
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
    let debugOption = BoolOption(shortFlag: "g", longFlag: "debug", required: false,
        helpMessage: "Enable debug output.")
    cli.addOptions(dirPath, debugOption)

    do {
        try cli.parse()
        debug = debugOption.value
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
            print ("The directory \(dir) does not exist.".red())
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
                print("error making POST request to \(ossindexURL)".red())
                print(error!)
                exit(1)
            }
            guard let responseData = data else {
                spinner.stop()
                print("Error: did not receive data".red())
                exit(1)
            }
            let response = String(data: responseData, encoding: .utf8)!
            if (debug)
            {
                print ("HTTP response: \(response)".blue())
            }
            if !response.hasPrefix("[{\"coordinates\"")
            {
                spinner.stop()
                print("Error: did not receive coordinate data".red())
                exit(1)
            }
            spinner.succeed(text: "Received \(responseData) from server.")

            apiResponse = response
            if (apiResponse == "") {
              print("Error: Empty response from server".red())
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
        }
        catch {
            print ("Error decoding JSON \(apiResponse): \(error).".red())
            exit(1)
        }

    }
    else {
        print("speedbump doesn't currently support package manager file \(f).".red())
    }
}
