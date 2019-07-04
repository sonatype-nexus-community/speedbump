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

func getPackages(file: String) -> Packages
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
let lockFiles = getLockFiles(dir: parseCli())
let p = getPackages(file: lockFiles[0])
print(p)
