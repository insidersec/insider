package visitor

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

func TestScopeLoading(t *testing.T) {
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
    inputFile := NewInputFile("test/placeholder.java", "test/placeholder.java", []byte(testClass))

    // This index points to the onCreate function, right before the opening parenthesis
    evidence := inputFile.CollectEvidenceSample(827)

    if evidence.HazardousScope != "onCreate" {
        t.Fatal("Should have found the onCreate method")
    }
}

func TestScopeAndImportsLoading(t *testing.T) {
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
    inputFile := NewInputFile("test/placeholder.java", "test/placeholder.java", []byte(testClass))

    for _, importOnFile := range inputFile.FileImports {
        if importOnFile != "android.database.sqlite.SQLiteDatabase" &&
            importOnFile != "android.database.sqlite.SQLiteOpenHelper" &&
            importOnFile != "com.synerise.sdk.core.Synerise" &&
            importOnFile != "com.synerise.sdk.core.persistence.sqllite.table.ClientTable" {
            t.Fatal("Didn't find all of the imports")
        }
    }
}

func TestImportsLoadingOnJSFile(t *testing.T) {
    testClass := `const utils = require('../lib/utils')
const insecurity = require('../lib/insecurity')
const models = require('../models/index')

module.exports = function retrieveUserList () {
  return (req, res, next) => {
    models.User.findAll().then(users => {
      const usersWithLoginStatus = utils.queryResultToJson(users)
      usersWithLoginStatus.data.forEach(user => {
        user.token = insecurity.authenticatedUsers.tokenOf(user)
        user.password = user.password ? user.password.replace(/./g, '*') : null
      })
      res.json(usersWithLoginStatus)
    }).catch(error => {
      next(error)
    })
  }
}
`

    inputFile := NewInputFile("test/", "test/placeholder.js", []byte(testClass))

    for _, importOnFile := range inputFile.FileImports {
        if importOnFile != "lib/utils" && importOnFile != "lib/insecurity" && importOnFile != "models/index" {
            t.Fatal("Failed to find the correct imports on JS files.")
        }
    }
}

func TestInputFileUses(t *testing.T) {
    testClass := `const utils = require('../lib/utils')
const insecurity = require('../lib/insecurity')
const models = require('../models/index')

module.exports = function retrieveUserList () {
  return (req, res, next) => {
    models.User.findAll().then(users => {
      const usersWithLoginStatus = utils.queryResultToJson(users)
      usersWithLoginStatus.data.forEach(user => {
        user.token = insecurity.authenticatedUsers.tokenOf(user)
        user.password = user.password ? user.password.replace(/./g, '*') : null
      })
      res.json(usersWithLoginStatus)
    }).catch(error => {
      next(error)
    })
  }
}
`

    dangerousClass := `/* jslint node: true */
const crypto = require('crypto')
const expressJwt = require('express-jwt')
const jwt = require('jsonwebtoken')
const sanitizeHtml = require('sanitize-html')
const z85 = require('z85')
const utils = require('./utils')
const fs = require('fs')

const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
module.exports.publicKey = publicKey
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

exports.hash = data => crypto.createHash('md5').update(data).digest('hex')
exports.hmac = data => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
`

    affectedFile := NewInputFile("/home/go", "/home/go/test/placeholder.js", []byte(testClass))
    dangerousFile := NewInputFile("/juice-shop-master", "/juice-shop-master/lib/insecurity.js", []byte(dangerousClass))

    t.Logf("dangerousFile::ImportReference -> %s", dangerousFile.ImportReference)
    t.Log("affectedFile::FileImport ->", affectedFile.FileImports)

    if !affectedFile.Uses(dangerousFile.ImportReference) {
        t.Fatal("Failed to identify security correlation between JS files")
    }
}
