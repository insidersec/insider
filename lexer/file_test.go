package lexer

import (
    "testing"
)

func TestFindContainingDeclarationInJava(t *testing.T) {
    testClass := `package com.synerise.sdk.core.persistence.sqllite;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.synerise.sdk.core.Synerise;
import com.synerise.sdk.core.persistence.sqllite.table.ClientTable;

public class CoreDbHelper extends SQLiteOpenHelper {
    public static final String DATABASE_NAME = "SyneriseCore.db";
    public static final int DATABASE_VERSION = 1;
    public static CoreDbHelper instance;

    public CoreDbHelper() {
        super(Synerise.getApplicationContext(), DATABASE_NAME, null, 1);
    }

    public static CoreDbHelper getInstance() {
        if (instance == null) {
            instance = new CoreDbHelper();
        }
        return instance;
    }

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
        sQLiteDatabase.execSQL(ClientTable.Queries.CREATE_TABLE);
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i2, int i3) {
        sQLiteDatabase.execSQL(ClientTable.Queries.DROP_TABLE);
    }
}`
    fakeFindingIndex := 819 // sQLiteDatabase. OBS.: The first one
    inputFile := NewInputFile("test", "test/dbHelper.java", []byte(testClass))

    declarationFinding := inputFile.FindContainingDeclaration(fakeFindingIndex)

    if declarationFinding == "" {
        t.Fatal("Should have returned a non-empty string")
    }

    if declarationFinding != "public void onCreate(SQLiteDatabase sQLiteDatabase) {" {
        t.Logf("Found: %s", declarationFinding)
        t.Fatal("Found wrong declaration")
    }
}

func TestFindContainingDeclarationInSwift(t *testing.T) {
    testClass := `//
//  AccountRouter.swift

import Alamofire

enum AccountRouter: URLRequestConvertible {
    
    case getMovement(MovementModel)
    case getBalance(BalanceModel)
    case trasnsacionalPassword(TransacionalPasswordModel)
    
    var method: Alamofire.HTTPMethod {
        switch self {
        case .getMovement:
            return .get
        case .getBalance:
            return .get
        case .trasnsacionalPassword:
            return .post
        }
    }
    
    var path: String {
        switch self {
        case .getMovement(let params):
            return "insec-api/v1/accounts/movements/\(params)"
        case .getBalance:
            return "insec-api/v1/accounts/balance"
        case .trasnsacionalPassword:
            return "insec-api/v1/users/passwords/transactional"
        }
    }
    
    func asURLRequest() throws -> URLRequest {
        
        let url = URL(string: Environment.rootURL.absoluteString)!
        var urlRequest = URLRequest(url: url.appendingPathComponent(path))
        urlRequest.httpMethod = method.rawValue
        
        let accessToken = DefaultsManager.shared().get(key: DefaultsManagerKeys.accessToken) ?? ""
        
         urlRequest.addValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        let params: (Codable?) = {
            switch self {
            case .getMovement(let params):
                return params
            case .getBalance(let params):
                return params
            case .trasnsacionalPassword(let params):
                return params
            }
        }()
        
        let encoding: ParameterEncoding = {
            switch method {
            case .get: return URLEncoding.default
            default: return JSONEncoding.default
            }
        }()
        
        return try encoding.encode(urlRequest, with: params?.dictionary)
    }
}
`
    fakeFindingIndex := 925 // let url = URL(string: Environment.rootURL.
    inputFile := NewInputFile("test", "test/dbHelper.java", []byte(testClass))

    declarationFinding := inputFile.FindContainingDeclaration(fakeFindingIndex)

    if declarationFinding == "" {
        t.Fatal("Should have returned a non-empty string")
    }

    if declarationFinding != "func asURLRequest() throws -> URLRequest {" {
        t.Logf("Found: %s", declarationFinding)
        t.Fatal("Found wrong declaration")
    }
}

func TestFindContainingDeclarationInSwiftShouldFailReturningAnEmptyString(t *testing.T) {
    testClass := `import Alamofire

enum AccountRouter: URLRequestConvertible {
    
    case getMovement(MovementModel)
    case getBalance(BalanceModel)
    case trasnsacionalPassword(TransacionalPasswordModel)
    
    var method: Alamofire.HTTPMethod {
        switch self {
        case .getMovement:
            return .get
        case .getBalance:
            return .get
        case .trasnsacionalPassword:
            return .post
        }
    }
    
    var path: String {
        switch self {
        case .getMovement(let params):
            return "insec-api/v1/accounts/movements/\(params)"
        case .getBalance:
            return "insec-api/v1/accounts/balance"
        case .trasnsacionalPassword:
            return "insec-api/v1/users/passwords/transactional"
        }
    }
    
    func asURLRequest() throws -> URLRequest {
        
        let url = URL(string: Environment.rootURL.absoluteString)!
        var urlRequest = URLRequest(url: url.appendingPathComponent(path))
        urlRequest.httpMethod = method.rawValue
        
        let accessToken = DefaultsManager.shared().get(key: DefaultsManagerKeys.accessToken) ?? ""
        
         urlRequest.addValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        let params: (Codable?) = {
            switch self {
            case .getMovement(let params):
                return params
            case .getBalance(let params):
                return params
            case .trasnsacionalPassword(let params):
                return params
            }
        }()
        
        let encoding: ParameterEncoding = {
            switch method {
            case .get: return URLEncoding.default
            default: return JSONEncoding.default
            }
        }()
        
        return try encoding.encode(urlRequest, with: params?.dictionary)
    }
}
`
    fakeFindingIndex := 581 // return "insec-api/v1/accounts/movements/\(params)"
    inputFile := NewInputFile("test", "test/AccountRouter.swift", []byte(testClass))

    declarationFinding := inputFile.FindContainingDeclaration(fakeFindingIndex)

    if declarationFinding != "" {
        t.Fatal("Should have returned a empty string")
    }

    if declarationFinding == "func asURLRequest() throws -> URLRequest {" {
        t.Fatal("Found a declaration where it shouldn't")
    }
}
