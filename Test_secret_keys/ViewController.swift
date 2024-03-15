//
//  ViewController.swift
//  Test_secret_keys
//
//  Created by apple on 13.03.2024.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {
    @IBOutlet weak var privateKeyTextView: UITextView!
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var opponentPublicKeyTextField: UITextField!
    @IBOutlet weak var encryptedMessageTextView: UITextView!
    @IBOutlet weak var decryptedMessageTextView: UITextView!
    
    let testMessage = "This is the test message for encrypt/decrypt"
    
    @IBOutlet weak var goButton: UIButton!
    override func viewDidLoad() {
        super.viewDidLoad()
        
        privateKeyTextView.delegate = self
        publicKeyTextView.delegate = self
        opponentPublicKeyTextField.delegate = self
        encryptedMessageTextView.delegate = self
        decryptedMessageTextView.delegate = self
        
        /// Setup
        encryptedMessageTextView.text = "Test message will be generated after selecting 'GO!' button"
        decryptedMessageTextView.text = "Test message will be generated after selecting 'GO!' button"
        opponentPublicKeyTextField.placeholder = "Don't forget paste public key here!!!"
        
        // privateKey generated
        let privateKey = P256.KeyAgreement.PrivateKey()
        privateKeyTextView.text = exportPrivateKey(privateKey)
        
        // publicKey generated
        let publicKey = P256.KeyAgreement.PrivateKey().publicKey
        publicKeyTextView.text = exportPublicKey(publicKey)
    }

    @IBAction func goButtonSelected(_ sender: Any) {
        encryptMessage(text: testMessage) { encryptedMessage, error in
            self.encryptedMessageTextView.text = encryptedMessage ?? (error?.localizedDescription ?? "Something went wrong")
            guard let encryptedMessage = encryptedMessage else { return }
            self.decryptMessage(text: encryptedMessage) { decryptedMessage, error in
                self.decryptedMessageTextView.text = decryptedMessage ?? (error?.localizedDescription ?? "Something went wrong")
            }
        }
    }
    
    func exportPrivateKey(_ privateKey: P256.KeyAgreement.PrivateKey) -> String {
        let rawPrivateKey = privateKey.rawRepresentation
        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
        return privateKeyBase64
    }
    
    func exportPublicKey(_ publicKey: P256.KeyAgreement.PublicKey) -> String {
        let rawPublicKey = publicKey.rawRepresentation
        let base64PublicKey = rawPublicKey.base64EncodedString()
        return base64PublicKey
    }
    
    func importPrivateKey(_ privateKey: String) throws -> P256.KeyAgreement.PrivateKey {
        let rawPrivateKey = Data(base64Encoded: privateKey)!
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
    }
    
    func importPublicKey(_ publicKey: String) throws -> P256.KeyAgreement.PublicKey {
        let rawPublicKey = Data(base64Encoded: publicKey)!
        return try P256.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
    }
    
    func encryptMessage(text: String, completion: @escaping (String?, Error?)->()) {
        do {
            let privateKey = try importPrivateKey(privateKeyTextView.text)
            let publicKey = try importPublicKey(opponentPublicKeyTextField.text ?? "")
            let symmetricKey = try prepareKeysPair(privateKey: privateKey, publicKey: publicKey)
            guard let textData = text.data(using: .utf8) else {
                completion(nil, nil)
                return }

            let encrypted = try AES.GCM.seal(textData, using: symmetricKey)
            let message = encrypted.combined?.base64EncodedString()
            completion(message, nil)
        } catch {
            completion(nil, error)
        }
    }
    
    func decryptMessage(text: String, completion: @escaping (String?, Error?)->()) {
        do {
            let privateKey = try importPrivateKey(privateKeyTextView.text)
            let publicKey = try importPublicKey(opponentPublicKeyTextField.text ?? "")
            let symmetricKey = try prepareKeysPair(privateKey: privateKey, publicKey: publicKey)
            
            guard let data = Data(base64Encoded: text) else {
                completion(nil, nil)
                return
            }
            
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            
            let rSensitiveMessage = String(data: decryptedData, encoding: .utf8)!
            
            completion(rSensitiveMessage, nil)
        } catch {
            completion(nil, error)
        }
    }
    
    func prepareKeysPair(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
//        let iv = "31348c0987c7".data(using: .utf8)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(), //iv ??
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        return symmetricKey
    }
}

extension ViewController: UITextFieldDelegate {
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        return true
    }
}

extension ViewController: UITextViewDelegate {
    func textView(_ textView: UITextView, shouldChangeTextIn range: NSRange, replacementText text: String) -> Bool {
        return true
    }
}
