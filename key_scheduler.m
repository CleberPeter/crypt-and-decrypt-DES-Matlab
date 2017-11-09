%Autor: Cleber Peter

%função que gera as 16 subchaves para o DES
%global_key_bin -> chave
%debug(0|1) -> possibilita visulizar informações internas da função,
%em tempo de execução
%roundKey_dec -> array das 16 chaves em decimal
%roundKey -> array das 16 chaves em binário de 48 bits
function  [roundKey, roundKey_dec] = key_scheduler(global_key_bin, debug)
    clc; % limpa terminal
    roundKey = zeros(16,48); % inicializa vetor 16x48
    roundKey_dec = zeros(16,8); % inicializa vetor 16x8
    
    key_PC1 = [ 57, 49, 41, 33, 25, 17 , 9, ...
     1, 58, 50, 42, 34, 26, 18, ...
     10, 2, 59, 51, 43, 35, 27, ...
     19, 11, 3, 60, 52, 44, 36, ...
     63, 55, 47, 39, 31, 23, 15, ...
     7, 62, 54, 46, 38, 30, 22, ...
     14, 6, 61, 53, 45, 37, 29, ...
     21, 13, 5, 28, 20, 12, 4 ]; % matriz de permutação/contração 1

    key_PC2 = [ 14, 17, 11, 24, 1, 5 , 3, 28, ...
     15, 6, 21, 10, 23, 19, 12, 4, ...
     26, 8, 16, 7, 27, 20, 13, 2, ...
     41, 52, 31, 37, 47, 55, 30, 40, ...
     51, 45, 33, 48, 44, 49, 39, 56, ...
     34, 53, 46, 42, 50, 36, 29, 32]; % matriz de permutação/contração 2

    rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, ...
     2, 2, 2, 2, 2, 1];% matriz que indica a quantidade de shift's para a esquerda
 
 
    key_permuted = global_key_bin(key_PC1(1:56)); % opera PC1 com global_key_bin
    
    key_permuted_c = key_permuted(1:28); % separa em parte alta e baixa
    key_permuted_d = key_permuted(29:56);
    
    for i=1:16  % varre as 16 chaves
    
        key_permuted_shited_c = circshift(key_permuted_c,[0 -1*rotations(i)]); % rotaciona n vezes para a esquerda
        key_permuted_shited_d= circshift(key_permuted_d,[0 -1*rotations(i)]);

        key_permuted_shifted = horzcat(key_permuted_shited_c,key_permuted_shited_d); % junta os vetores novamente

        key_final = key_permuted_shifted(key_PC2(1:48)); % opera PC2 com key_permuted_shifted
        
        roundKey(i,:) = key_final;  % copia o resultado para o vetor resposta
        
        j = 1;
        for k=1:8 % separa em 8 grupos de 6 bits e converte pra decimal
            roundKey_dec(i,k) = bi2de(key_final(j:j+5),'left-msb');  % cria vetor resposta decimal
            j=j+6;
        end

        key_permuted_c = key_permuted_shited_c; % copia resposta para a entrada do próximo passo
        key_permuted_d = key_permuted_shited_d;
    end
    
    if debug == 1
        disp(roundKey_dec); % imprime informações para debug
    end
    
end


    
