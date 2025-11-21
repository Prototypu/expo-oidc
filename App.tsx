import React, { useState } from 'react';
import { StyleSheet, Text, View, Button, ScrollView, SafeAreaView, ActivityIndicator, Alert } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import * as Linking from 'expo-linking';
import * as AuthService from './services/authService';
import { PKCEData, TokenResponse } from './services/authService';

export default function App() {
  const [pkceData, setPkceData] = useState<PKCEData | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('请点击下方按钮登录');

  const handleLogin = async () => {
    setLoading(true);
    setStatus('正在准备授权...');
    setTokens(null);

    try {
      // 1. Generate PKCE Data (state, verifier, challenge)
      const generatedPkceData = await AuthService.generatePKCEData();
      setPkceData(generatedPkceData);

      // 2. Build Authorization URL
      const authUrl = AuthService.getAuthUrl(generatedPkceData);
      console.log('Opening Auth URL:', authUrl);

      // 3. Open Web Browser
      // We use openAuthSessionAsync to listen for the redirect scheme automatically
      const result = await WebBrowser.openAuthSessionAsync(
        authUrl,
        AuthService.AUTH_CONFIG.REDIRECT_URI
      );

      if (result.type === 'success' && result.url) {
        setStatus('授权回调成功，正在校验...');
        await handleCallback(result.url, generatedPkceData);
      } else if (result.type === 'cancel') {
        setStatus('用户取消了登录');
        setLoading(false);
      } else {
        setStatus(`登录未完成: ${result.type}`);
        setLoading(false);
      }

    } catch (error: any) {
      console.error(error);
      setStatus(`发生错误: ${error.message}`);
      Alert.alert('Error', error.message);
      setLoading(false);
    }
  };

  const handleCallback = async (url: string, currentPkceData: PKCEData) => {
    try {
      // 4. Parse Callback
      const params = AuthService.parseCallbackUrl(url);
      
      if (!params) {
        throw new Error('回调 URL 中未找到 code 或 state');
      }

      const { code, state } = params;

      // 5. Validate State
      if (state !== currentPkceData.state) {
        throw new Error('State 校验失败！可能存在 CSRF 风险。');
      }

      setStatus('正在交换 Token...');

      // 6. Exchange Code for Token
      const tokenResponse = await AuthService.exchangeToken(code, currentPkceData.codeVerifier);
      
      setTokens(tokenResponse);
      setStatus('登录成功！');
    } catch (error: any) {
      setStatus(`Token 交换失败: ${error.message}`);
      Alert.alert('Token Error', error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <Text style={styles.title}>Expo OAuth PKCE Demo</Text>
        
        <View style={styles.card}>
          <Text style={styles.statusLabel}>状态: <Text style={styles.statusText}>{status}</Text></Text>
        </View>

        {loading && <ActivityIndicator size="large" color="#007AFF" style={styles.loader} />}

        {!tokens ? (
          <View style={styles.buttonContainer}>
            <Button 
              title="使用 IM 登录" 
              onPress={handleLogin} 
              disabled={loading} 
            />
          </View>
        ) : (
          <View style={styles.resultContainer}>
            <Text style={styles.resultTitle}>认证成功</Text>
            
            <View style={styles.tokenBlock}>
              <Text style={styles.tokenLabel}>Access Token:</Text>
              <Text style={styles.tokenValue}>{tokens.access_token}</Text>
            </View>

            <View style={styles.tokenBlock}>
              <Text style={styles.tokenLabel}>Refresh Token:</Text>
              <Text style={styles.tokenValue}>{tokens.refresh_token || 'N/A'}</Text>
            </View>

            {tokens.id_token && (
              <View style={styles.tokenBlock}>
                <Text style={styles.tokenLabel}>ID Token (Raw):</Text>
                <Text style={styles.tokenValue}>{tokens.id_token}</Text>
              </View>
            )}
            
            <Button title="清除数据 (重置)" onPress={() => { setTokens(null); setStatus('请点击下方按钮登录'); }} />
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  scrollContent: {
    padding: 20,
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginVertical: 20,
    color: '#333',
  },
  card: {
    width: '100%',
    backgroundColor: 'white',
    padding: 15,
    borderRadius: 10,
    marginBottom: 20,
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
  },
  statusLabel: {
    fontSize: 16,
    color: '#666',
  },
  statusText: {
    color: '#333',
    fontWeight: '500',
  },
  loader: {
    marginBottom: 20,
  },
  buttonContainer: {
    width: '100%',
    marginTop: 10,
  },
  resultContainer: {
    width: '100%',
  },
  resultTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: 'green',
    textAlign: 'center',
  },
  tokenBlock: {
    backgroundColor: '#fff',
    padding: 15,
    borderRadius: 8,
    marginBottom: 15,
    borderWidth: 1,
    borderColor: '#ddd',
  },
  tokenLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 5,
    color: '#444',
  },
  tokenValue: {
    fontSize: 12,
    fontFamily: 'Courier',
    color: '#555',
  },
});
