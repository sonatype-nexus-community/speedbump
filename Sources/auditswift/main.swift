import Foundation
import CommandLineKit
import ColorizeSwift

func printLogo() {
    let t = try? Figlet(fontFile:"fonts/chunky.flf")?.drawText(text: "AuditSwift")
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
    print("\n")  
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
    cli.addOptions(dirPath)
    
    do {
        try cli.parse()
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
        return lockFiles
    }
    catch {
        print ("Error enumerating files in directory \(dir).".red())
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
        print ("Error reading JSON from file \(file).".red())
        exit(1)
    }
}


printLogo()
let d = parseCli()
let lockFiles = getLockFiles(dir: d)

if lockFiles.count == 0 {
    print ("Did not find any package manager files in directory \(d)".red())
    exit(1)
}
for f in lockFiles {
    if f.hasSuffix("Package.resolved") {
        print("Using Swift Package Manager file \(f).".green())
        let p = getSPMPackages(file: f)
        print("Parsed \(p.object!.pins!.count) packages from \(f).")
        var coords = [String]()
        for pin in p.object!.pins!
        {
            coords.append("pkg:gem/\(pin.package!)@\(pin.package!)\(pin.state!.version!)")
        }
        let coordinates = ["coordinates": coords]
        print(coordinates)
        let json = String(data: try! JSONSerialization.data(withJSONObject: coordinates), encoding: .utf8)!
        print(json)
    }
    else {
        print("auditswift doesn't currently support package manager file \(f).".red())
    }
}


