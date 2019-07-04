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

func parseCli() {
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
    } 
    catch {
        print("Audit a Swift package's dependencies for security vulnerabilities.\n")
        cli.printUsage(error)
    }
}
printLogo()
parseCli()

